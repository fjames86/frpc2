;;;; Copyright (c) Frank James 2016 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(defpackage #:rpcbind
  (:use #:cl #:frpc2)
  (:export #:rpcbind 
	   #:start-rpcbind
	   #:stop-rpcbind))

(in-package #:rpcbind)

;; ------------------- logging -------------------------

(defvar *rpcbind-tag* (babel:string-to-octets "RPCB"))
(defun rpcbind-log (lvl format-string &rest args)
  (when *frpc2-log*
    (pounds.log:write-message *frpc2-log* lvl
			      (apply #'format nil format-string args)
			      :tag *rpcbind-tag*)))

			      
;; -------------- globals ------------------


(defvar *mappings* (make-list 32))
(defparameter *heartbeat-age* nil
  "If non-nil, will call the nullproc periodically after this many seconds. 
Typical values might be 5 minutes.")
(defparameter *purge-age* nil
  "If non-nil, is the number of seconds without reply afterwhich the mapping will be purged. A typical value might be 6 minutes.")

;; --------------- RPC Handlers ----------------

;; the set and unset handlers may only be called from loopback device 
(defun loopback-or-fail (server)
  (let ((pfd (simple-rpc-server-rpfd server)))
    (typecase pfd 
      (udp-pollfd 
       (unless (fsocket:loopback-p (udp-pollfd-addr pfd))
	 (error 'auth-error :stat :tooweak)))
      (tcp-pollfd 
       (unless (fsocket:loopback-p (tcp-pollfd-addr pfd))
	 (error 'auth-error :stat :tooweak))))))


;; proc 0
(defun handle-rpcbind-null (server arg)
  (declare (ignore server arg))
  (rpcbind-log :info "START NULL")
  nil)

;; proc 1
(defun handle-rpcbind-set (server mapping)
  (rpcbind-log :info "START SET")
  (loopback-or-fail server)

  (let ((oldest 0))
    (do ((mappings *mappings* (cdr mappings))
         (i 0 (1+ i))
         (age 0))
        ((null mappings))
      (let ((m (car mappings)))
        (cond
          ((null m)
           (setf oldest i
                 mappings nil))
	  ((and (= (mapping-program (car m)) (mapping-program mapping))
		(eq (mapping-protocol (car m)) (mapping-protocol mapping)))
	   ;; program already exists on this protocol, don't add
	   (return-from handle-rpcbind-set nil))
          (t
           (destructuring-bind (mp last-seen next-heartbeat) m
             (declare (ignore mp next-heartbeat))
             (when (or (zerop age) (< last-seen age))
               (setf oldest i
                     age last-seen)))))))
    (setf (nth oldest *mappings*)
          (list mapping (get-universal-time)
		(when *heartbeat-age*
		  (+ (get-universal-time) *heartbeat-age*))))
    t))
         
;; proc 2 
(defun handle-rpcbind-unset (server mapping)
  (rpcbind-log :info "START UNSET")
  (loopback-or-fail server)

  (do ((mappings *mappings* (cdr mappings)))
      ((null mappings))
    (when (car mappings)
      (destructuring-bind (mp last-seen next-heartbeat) (car mappings)
	(declare (ignore last-seen next-heartbeat))
	(when (and (= (mapping-program mapping) (mapping-program mp))
		   (eq (mapping-protocol mapping) (mapping-protocol mp)))
	  ;; found it. clear out entry 
	  (setf (car mappings) nil)))))
  t)

;; proc 3 
(defun handle-rpcbind-getport (server mapping)
  (declare (ignore server))
  (rpcbind-log :info "START GETPORT")
  (dolist (m *mappings*)
    (when m
      (destructuring-bind (mp last-seen next-heartbeat) m
	(declare (ignore last-seen next-heartbeat))
	(when (and (= (mapping-program mapping) (mapping-program mp))
		   (= (mapping-version mapping) (mapping-version mp))
		   (eq (mapping-protocol mapping) (mapping-protocol mp)))
	  (return-from handle-rpcbind-getport
	    (mapping-port mp))))))
  0)
          
;; proc 4     
(defun handle-rpcbind-dump (server arg)
  (declare (ignore server arg))
  (rpcbind-log :info "START DUMP")
  (mapcan (lambda (m)
            (when m
              (list (car m))))
          *mappings*))

;; -------- proc 5 (callit) requires special treatment -----------

(defun process-callit-reply (server blk arg)
  (let ((msg (simple-rpc-server-msg server)))
    ;; we don't want to send any reply in the event that the call failed
    (handler-bind ((error (lambda (e)
			    (rpcbind-log :info "Callit failed ~A" e)
			    (return-from process-callit-reply nil))))
      (frpc2::rpc-reply-verf msg)))
  
  (destructuring-bind (raddr rxid rpfd) arg
    (rpcbind-log :info "Callit reply ~A" rxid)

    ;; send the callit reply back to the reply address
    (let ((rblk (drx:xdr-block (- (drx:xdr-block-count blk)
				  (drx:xdr-block-offset blk)))))
      (rpcbind-log :info "Callit reply ~A bytes"
		   (- (drx:xdr-block-count blk)
		      (drx:xdr-block-offset blk)))
      (do ((i (drx:xdr-block-offset blk) (1+ i)))
          ((= i (drx:xdr-block-count blk)))
        (setf (aref (drx:xdr-block-buffer rblk) (- i (drx:xdr-block-offset blk)))
              (aref (drx:xdr-block-buffer blk) i)))
      (let ((res (list (fsocket:sockaddr-in-port
			(udp-pollfd-addr
			 (simple-rpc-server-rpfd server)))
                       (list (drx:xdr-block-buffer rblk)
			     0 (- (drx:xdr-block-count blk)
				  (drx:xdr-block-offset blk))))))
        (drx:reset-xdr-block blk)
	(encode-rpc-msg blk (make-rpc-reply rxid :success))
	(encode-callit-res blk res)
	(etypecase rpfd
	  (udp-pollfd
	   (rpcbind-log :trace "Replying to UDP client")
	   (fsocket:socket-sendto (fsocket:pollfd-fd rpfd)
				  (drx:xdr-block-buffer blk)
				  raddr 
				  :start 0 :end (drx:xdr-block-offset blk)))
	  (tcp-pollfd
	   (rpcbind-log :trace "Replying to TCP client")
	   ;; need to send the byte count first
	   (let ((cblk (drx:xdr-block 4)))
	     (drx:encode-uint32 cblk (logior (drx:xdr-block-offset blk) #x80000000))
	     (let ((cnt (fsocket:socket-send (fsocket:pollfd-fd rpfd)
					     (drx:xdr-block-buffer cblk))))
	       (unless (= cnt 4) (rpcbind-log :trace "Short write"))))
	   (let ((cnt (fsocket:socket-send (fsocket:pollfd-fd rpfd)
					   (drx:xdr-block-buffer blk)
					   :start 0 :end (drx:xdr-block-offset blk))))
	     (unless (= cnt (drx:xdr-block-offset blk)) (rpcbind-log :trace "Short write"))))))))
    nil)

(defun handle-rpcbind-callit (server arg)
  ;; packup and send the arg to the program handler
  (rpcbind-log :info "START CALLIT ~A:~A:~A~%" (callit-arg-program arg) (callit-arg-version arg) (callit-arg-proc arg))
  
  (let ((mapping (car (find-if (lambda (m)
                                 (let ((mp (car m)))
				   (when mp 
				     (and (= (callit-arg-program arg) (mapping-program mp))
					  (= (callit-arg-version arg) (mapping-version mp))
					  (eq (mapping-protocol mp) :udp)))))
                               *mappings*)))
        (pfd (find-if (lambda (p)
                        (typep p 'udp-pollfd))
                      (fsocket:poll-context-fds (simple-rpc-server-pc server)))))
    
    ;; if no mapping found then silently discard
    (unless mapping
      (rpcbind-log :info "No mapping found")
      (rpc-discard-call))

    (when pfd 
      (let ((blk (udp-pollfd-blk pfd))
	    (carg (destructuring-bind (buf start end) (callit-arg-args arg)
		    (list (subseq buf start end) 0 (- end start)))))
	(drx:reset-xdr-block blk)
	(let ((xid (encode-rpc-call blk
				    #'drx:encode-void 
				    nil
				    (callit-arg-program arg)
				    (callit-arg-version arg)
				    (callit-arg-proc arg)
				    :xid (rpc-msg-xid (simple-rpc-server-msg server)))))

	  ;; encode the args directly 
	  (dotimes (i (third carg))
	    (setf (aref (drx:xdr-block-buffer blk)
			(+ (drx:xdr-block-offset blk) i))
		  (aref (first carg) i)))
	  (incf (drx:xdr-block-offset blk) (third carg))
	  
	  (fsocket:socket-sendto (fsocket:pollfd-fd pfd)
				 (drx:xdr-block-buffer blk)
				 (fsocket:make-sockaddr-in :addr #(127 0 0 1)
							   :port (mapping-port mapping))
				 :start 0 :end (drx:xdr-block-offset blk))

	  (rpcbind-log :info "Awaiting reply for ~A" xid)
	  (simple-rpc-server-await-reply server xid #'process-callit-reply
					 :context (list (etypecase pfd
							  (udp-pollfd (udp-pollfd-addr pfd))
							  (tcp-pollfd (tcp-pollfd-addr pfd)))
							xid
							(simple-rpc-server-rpfd server)))))))
    
  ;; we don't actually want to exit this function normally because otherwise
  ;; we'd need to block waiting for a reply. 
  ;; Instead we exit early and send the reply later when we receive a response
  ;; using the simple-rpc-server waiter API.
  (rpc-discard-call))


(defconstant +rpcbind-program+ 100000)
(defconstant +rpcbind-version+ 2)

(define-rpc-server rpcbind (+rpcbind-program+ +rpcbind-version+)
  (null :void :void)
  (set mapping :boolean)
  (unset mapping :boolean)
  (getport mapping :uint32)
  (dump :void mapping-list-opt)
  (callit callit-arg callit-res))



(defun process-heartbeat-reply (server blk arg)
  (declare (ignore server blk))
  (destructuring-bind (program version) arg
    (rpcbind-log :info "Heartbeat reply ~A ~A" program version)
    (let ((now (get-universal-time)))
      ;; find the mapping entry and update its timestamp
      (dolist (m *mappings*)
	(when m 
	  (destructuring-bind (mp last-seen next-heartbeat) m
	    (declare (ignore last-seen next-heartbeat))
	    (when (and (= (mapping-program mp) program)
		       (= (mapping-version mp) version))
	      (setf (second m) now
		    (third m) (when *heartbeat-age*
				(+ now *heartbeat-age*))))))))))

(defun send-heartbeat (server fd blk mapping)
  (drx:reset-xdr-block blk)
  ;; encode a call and send it
  (rpcbind-log :info "Heartbeating ~A on port ~A" (mapping-program mapping) (mapping-port mapping))
  
  (let ((xid (encode-rpc-call blk #'drx:encode-void nil
			      (mapping-program mapping)
			      (mapping-version mapping)
			      0)))

    (fsocket:socket-sendto fd 
			   (drx:xdr-block-buffer blk)
			   (fsocket:make-sockaddr-in :addr #(127 0 0 1)
						     :port (frpc2:mapping-port mapping))
			   :start 0 :end (drx:xdr-block-offset blk))

    (simple-rpc-server-await-reply server xid
				   #'process-heartbeat-reply
				   :context (list (mapping-program mapping)
						  (mapping-version mapping)))))

(defvar *server* nil)

(defun run-rpcbind (server)

  ;; main loop 
  (do ((now (get-universal-time) (get-universal-time)))
      ((simple-rpc-server-exiting server))
    (simple-rpc-server-process server)

    ;; call the null proc on each of the registered programs
    (let ((pfd (find-if (lambda (p)
                          (typep p 'udp-pollfd))
                        (fsocket:poll-context-fds (simple-rpc-server-pc server)))))
      (when pfd
        (let ((blk (udp-pollfd-blk pfd)))
          (dolist (m *mappings*)
            (when m
              (destructuring-bind (mapping last-seen next-heartbeat) m
                (declare (ignore last-seen))
                (when (and (eq (mapping-protocol mapping) :udp)
			   next-heartbeat 
                           (> now next-heartbeat))
		  (send-heartbeat server (fsocket:pollfd-fd pfd) 
				  blk mapping)
		  ;; add 5 seconds to the next heartbeat age so we don't spin if no reply received 
		  (incf (third m) 5))))))))

    ;; purge any mappings which are not responding to heartbeats 
    (do ((mappings *mappings* (cdr mappings)))
        ((null mappings))
      (let ((m (car mappings)))
	(when m
	  (destructuring-bind (mapping last-seen next-heartbeat) m
	    (declare (ignore next-heartbeat))
	    (when (and *purge-age* (> now (+ last-seen *purge-age*)))
	      (rpcbind-log :info "Purging ~A" (mapping-program mapping))
	      (setf (car mappings) nil))))))))

(defun start-rpcbind ()
  (unless *server*
    (setf *server* (simple-rpc-server-construct (list (make-rpcbind-program))
						:udp-ports '(111)
						:tcp-ports '(111)))

    ;; ensure we have rpcbind set in the mappings 
    (handle-rpcbind-set *server* (make-mapping :program 100000 :version 2 :protocol :udp :port 111))
    (handle-rpcbind-set *server* (make-mapping :program 100000 :version 2 :protocol :tcp :port 111))

    (simple-rpc-server-start *server* #'run-rpcbind)))

(defun stop-rpcbind ()
  (when *server*
    (simple-rpc-server-stop *server*)
    (simple-rpc-server-destruct *server*)
    (setf *server* nil)))


