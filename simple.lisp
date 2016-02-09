;;;; Copyright (c) Frank James 2016 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(in-package #:frpc2)


;; nice and simple rpc server sugar coating
(defclass udp-pollfd (fsocket:pollfd)
  ((addr :initform nil :accessor udp-pollfd-addr)
   (blk :initform (xdr-block (* 1024 32)) :accessor udp-pollfd-blk)))
  
(defclass tcp-listen-pollfd (fsocket:pollfd)
  ())
(defclass tcp-pollfd (fsocket:pollfd)
  ((addr :initarg :addr :reader tcp-pollfd-addr)
   (timestamp :initform (get-universal-time) :accessor tcp-pollfd-timestamp)
   (blk :initform (xdr-block (* 1024 32)) :accessor tcp-pollfd-blk)
   (count :initform nil :accessor tcp-pollfd-count)
   (last :initform nil :accessor tcp-pollfd-last)))
(defconstant +tcp-purge-age+ 60)  

(defclass simple-rpc-server (rpc-server)
  ((pc :initform nil :accessor simple-rpc-server-pc)
   (calls :initform (make-list 32) :accessor simple-rpc-server-calls)
   (msg :initform nil :accessor simple-rpc-server-msg)
   (rpfd :initform nil :accessor simple-rpc-server-rpfd)
   (exiting :initform nil :accessor simple-rpc-server-exiting)
   (timeout :initform 1000 :accessor simple-rpc-server-timeout)
   (thread :initform nil :accessor simple-rpc-server-thread)))

(defstruct call 
  xid 
  timeout
  fn
  arg 
  static-p
  purge-cb)

(defun simple-rpc-server-await-reply (server xid fn &key context (timeout 2000) static-p purge-cb)
  "Enqueue a waiter for a reply to a call made with transaction id XID. The function FN will be invoked with 
three arguments: the server instance, an xdr block containing the result XDR and the user supplied context value.

SERVER ::= RPC-SERVER instance
XID ::= transaction ID to wait for a reply to
FN ::= function of 3 parameters (server blk context) where server is the RPC 
server instance, blk is the XDR result block and context is the input CONTEXT.
CONTEXT ::= value to pass into the callback with
TIMEOUT ::= number of milliseconds seconds to wait for the reply before the waiter is purged.
STATIC-P ::= if true, the waiter will NOT be purged when the first reply is received. Thus, it allows processing
multiple replies to the same RPC. This is useful when broadcasting (or multicasting) RPCs to a large number of 
peers. 
PURGE-CB ::= a function to call when this waiter is purged. The function accepts
the same arguments as the normal FN, except the BLK is nil.

If TIMEOUT is NIL then the waiter will not be purged until a manual call to SIMPLE-RPC-SERVER-PURGE-CALLS.
If STATIC-P is true then the waiter will not be purged until it either times out or is manually purged.
"
  (do ((calls (simple-rpc-server-calls server) (cdr calls)))
      ((null calls))
    (when (null (car calls))
      (setf (car calls) (make-call :xid xid
				   :timeout (when timeout (+ (truncate (* 1000 (get-internal-real-time))
								       internal-time-units-per-second)
							     timeout))
				   :fn fn
				   :arg context 
				   :static-p static-p
				   :purge-cb purge-cb))
      (frpc2-log :trace "[~A] Enqueuing call waiter" xid)
      (return-from simple-rpc-server-await-reply t)))
  (frpc2-log :info "Failed to enqueue call waiter")
  nil)
       
(defun simple-rpc-server-purge-calls (server &key purge-static xid)
  "Purge all enqueued call waiters that have timed out. 
SERVER ::= server instance
PURGE-STATIC ::= if true then both static waiters and waiters with no timeout will additonally be purged.
XID ::= if supplied, waiters for this XID will be purged. 
"
  (do ((calls (simple-rpc-server-calls server) (cdr calls))
       (now (truncate (* 1000 (get-internal-real-time)) internal-time-units-per-second)))
      ((null calls))
    (let ((call (car calls)))
      (when call
	(cond 
	  ((and xid (= xid (call-xid call)))
	   ;; run the purge callback if one is defined 
	   (when (call-purge-cb call)
	     (ignore-errors (funcall (call-purge-cb call) nil (call-arg call))))	  
	   (setf (car calls) nil))
	  (t 
	   (let ((timeout (call-timeout call)))
	     ;; if a timeout was set and it's less than now then remove it 
	     (when (or (and timeout (< timeout now))
		       (and purge-static (or (null timeout) (call-static-p call))))
	       (frpc2-log :trace "[~A] Purging call" (call-xid call))
	       ;; run the purge callback if one is defined 
	       (when (call-purge-cb call)
		 (ignore-errors (funcall (call-purge-cb call) nil (call-arg call))))
	       (setf (car calls) nil)))))))))

(defun process-simple-rpc-server-reply (server xid blk)
  (let ((call (find-if (lambda (c) (and c (= (call-xid c) xid)))
		       (simple-rpc-server-calls server))))
    (when call
      (frpc2-log :trace "Processing reply message")
      (ignore-errors (funcall (call-fn call) server blk (call-arg call))))))

;; -------------------------------------------------

(defun process-simple-rpc-server-udp (server pollfd)
  ;; update the timestamp   
  (let ((blk (udp-pollfd-blk pollfd)))
    (reset-xdr-block blk)
    (multiple-value-bind (count raddr) (fsocket:socket-recvfrom (fsocket:pollfd-fd pollfd)
                                                                (xdr-block-buffer blk)
                                                                :start 0
                                                                :end (xdr-block-count blk))
      (setf (udp-pollfd-addr pollfd) raddr
            (xdr-block-offset blk) 0
            (xdr-block-count blk) count
            (simple-rpc-server-rpfd server) pollfd)

      (let ((msg (decode-rpc-msg blk)))
        (setf (simple-rpc-server-msg server) msg)
        (ecase (xunion-tag (rpc-msg-body msg))
          (:call (frpc2-log :info "CALL UDP ~A:~A ~A:~A:~A [~A]"  
			    (fsocket:sockaddr-in-addr raddr) (fsocket:sockaddr-in-port raddr)
			    (call-body-program (xunion-val (rpc-msg-body msg))) 
			    (call-body-version (xunion-val (rpc-msg-body msg))) 
			    (call-body-proc (xunion-val (rpc-msg-body msg)))
			    (rpc-msg-xid msg))
		 (when (process-rpc-call server blk msg)
		   (frpc2-log :trace "SENDTO ~A" raddr)
                   (fsocket:socket-sendto (fsocket:pollfd-fd pollfd)
                                          (xdr-block-buffer blk)
                                          raddr
                                          :start 0 :end (xdr-block-offset blk))))
          (:reply (frpc2-log :info "REPLY UDP ~A:~A" 
			     (fsocket:sockaddr-in-addr raddr) (fsocket:sockaddr-in-port raddr))
		  (process-simple-rpc-server-reply server (rpc-msg-xid msg) blk)))))))

;; TODO: check this function.
(defun process-simple-rpc-server-tcp (server pollfd)
  ;; ready to read on the connection. We need to keep reading until we have received all the fragments
  (setf (tcp-pollfd-timestamp pollfd) (get-universal-time))
  (cond
    ((null (tcp-pollfd-count pollfd))
     ;; no fragment count, read that first
     (let* ((fblk (xdr-block 4))
            (rcnt (fsocket:socket-recv (fsocket:pollfd-fd pollfd)
                                       (xdr-block-buffer fblk)
                                       :start 0
                                       :end (xdr-block-count fblk))))
       (cond
         ((zerop rcnt)
          ;; graceful shutdown at the other end, close connection
	  (frpc2-log :trace "Graceful close")
          (fsocket:close-socket (fsocket:pollfd-fd pollfd))
          (fsocket:poll-unregister (simple-rpc-server-pc server) pollfd))
         (t
          (let ((rcount (decode-uint32 fblk)))
            (setf (tcp-pollfd-count pollfd) (logand rcount #x7fffffff)
                  (tcp-pollfd-last pollfd) (not (zerop (logand rcount #x80000000)))))))))
    (t 
     ;; keep reading until we have read the count bytes
     (let* ((blk (tcp-pollfd-blk pollfd))
            (count (tcp-pollfd-count pollfd))
            (cnt (fsocket:socket-recv (fsocket:pollfd-fd pollfd)
                                      (xdr-block-buffer blk)
                                      :start (xdr-block-offset blk)
                                      :end (+ (xdr-block-offset blk) count))))
       (cond
         ((zerop cnt)
          ;; reading zero bytes indicates a graceful shutdown at the other end
	  (frpc2-log :trace "Graceful close")
          (fsocket:close-socket (fsocket:pollfd-fd pollfd))
          (fsocket:poll-unregister (simple-rpc-server-pc server) pollfd))
         (t
          (incf (xdr-block-offset blk) cnt)
          (decf (tcp-pollfd-count pollfd) cnt)

          (when (zerop (tcp-pollfd-count pollfd))
            (cond
              ((tcp-pollfd-last pollfd)
               (setf (xdr-block-count blk) (xdr-block-offset blk)
                     (xdr-block-offset blk) 0
		     (tcp-pollfd-count pollfd) nil
		     (tcp-pollfd-last pollfd) nil)
               (let ((msg (decode-rpc-msg blk)))
                 (setf (simple-rpc-server-msg server) msg
                       (simple-rpc-server-rpfd server) pollfd)
                 (ecase (xunion-tag (rpc-msg-body msg))
                   (:call (frpc2-log :info "[~A] CALL TCP ~A:~A ~A:~A:~A"
				     (rpc-msg-xid msg)
				     (fsocket:sockaddr-in-addr (tcp-pollfd-addr pollfd)) 
				     (fsocket:sockaddr-in-port (tcp-pollfd-addr pollfd))
				     (call-body-program (xunion-val (rpc-msg-body msg))) 
				     (call-body-version (xunion-val (rpc-msg-body msg))) 
				     (call-body-proc (xunion-val (rpc-msg-body msg))))

			  (cond
			    ((not (process-rpc-call server blk msg))
			     (frpc2-log :trace "No reply"))
			    (t 
                            ;; send the fragment header
                            (let ((hblk (xdr-block 4)))
			      (frpc2-log :info "[~A] REPLY TCP Length ~A"
					 (rpc-msg-xid msg)
					 (xdr-block-offset blk))
                              (encode-uint32 hblk (logior (xdr-block-offset blk) #x80000000))
			      ;; TODO: check for a short write
			      (fsocket:socket-send (fsocket:pollfd-fd pollfd)
							       (xdr-block-buffer hblk)
							       :start 0 :end (xdr-block-offset hblk)))
                            ;; send payload
			    ;; TODO: check for a short write
                            (fsocket:socket-send (fsocket:pollfd-fd pollfd)
							     (xdr-block-buffer blk)
							     :start 0 :end (xdr-block-offset blk))
			    (reset-xdr-block blk))))
                   (:reply (frpc2-log :info "[~A] REPLY TCP ~A:~A"
				      (rpc-msg-xid msg)
				      (fsocket:sockaddr-in-addr (tcp-pollfd-addr pollfd)) 
				      (fsocket:sockaddr-in-port (tcp-pollfd-addr pollfd)))
			   (process-simple-rpc-server-reply server (rpc-msg-xid msg) blk)))))
              (t
               (setf (tcp-pollfd-count pollfd) nil))))))))))
                       
(defun simple-rpc-server-process (server)
  (fsocket:doevents (pollfd event) (fsocket:poll (simple-rpc-server-pc server)
						 :timeout (simple-rpc-server-timeout server))
    (etypecase pollfd
      (udp-pollfd
       (handler-case (process-simple-rpc-server-udp server pollfd)
         (error (e)
	   (frpc2-log :error "UDP ~A" e)
           nil)))
      (tcp-listen-pollfd
       ;; ready to accept a TCP connection
       (handler-case 
           (multiple-value-bind (fd raddr) (fsocket:socket-accept (fsocket:pollfd-fd pollfd))
	     (frpc2-log :info "ACCEPT ~A" (fsocket:sockaddr-in-addr raddr))
             (fsocket:poll-register (simple-rpc-server-pc server)
                                    (make-instance 'tcp-pollfd
                                                   :fd fd
                                                   :events (fsocket:poll-events :pollin :pollhup)
                                                   :addr raddr)))
         (error (e)
	   (frpc2-log :error "TCP ACCEPT ~A" e)
           nil)))
      (tcp-pollfd
       (ecase event
         (:pollin
          (handler-case (process-simple-rpc-server-tcp server pollfd)
            (error (e)
	      (frpc2-log :error "TCP ~A" e)
              (fsocket:close-socket (fsocket:pollfd-fd pollfd))
              (fsocket:poll-unregister (simple-rpc-server-pc server) pollfd))))
         ((:pollhup :pollerr)
	  (when (fsocket:pollfd-fd pollfd)
	    (fsocket:close-socket (fsocket:pollfd-fd pollfd))
	    (fsocket:poll-unregister (simple-rpc-server-pc server) pollfd)
	    (setf (fsocket:pollfd-fd pollfd) nil)))))))

  ;; purge any outstanding calls that have timed out
  (simple-rpc-server-purge-calls server)

  ;; purge any tcp connections that are stale
  (let ((now (get-universal-time)))
    (dolist (pollfd (fsocket:poll-context-fds (simple-rpc-server-pc server)))
      (when (and (typep pollfd 'tcp-pollfd)
                 (> now
		    (+ (tcp-pollfd-timestamp pollfd) +tcp-purge-age+)))
	(frpc2-log :trace "Purging connection to ~A" (tcp-pollfd-addr pollfd))
        (fsocket:close-socket (fsocket:pollfd-fd pollfd))
        (fsocket:poll-unregister (simple-rpc-server-pc server) pollfd))))

  nil)

(defun simple-rpc-server-destruct (server)
  ;; tell rpcbind we are going away
  (with-rpc-client (c udp-client 
		      :addr (fsocket:sockaddr-in #(127 0 0 1) 111))
    (dolist (progs (rpc-server-programs server))
      (let ((program (first progs))
	    (version (second progs)))
	(dolist (pfd (fsocket:poll-context-fds (simple-rpc-server-pc server)))
	  (handler-case 
	      (typecase pfd 
		(udp-pollfd 
		 (call-rpcbind-unset c (make-mapping :program program
						     :version version
						     :protocol :udp
						     :port 0)))
		(tcp-pollfd 
		 (call-rpcbind-unset c (make-mapping :program program
						     :version version
						     :protocol :tcp
						     :port 0))))
	    (error (e)
	      (frpc2-log :error "Failed to unset mapping: ~A" e)))))))
	     
  ;; close all fds
  (dolist (pfd (fsocket:poll-context-fds (simple-rpc-server-pc server)))
    (fsocket:close-socket (fsocket:pollfd-fd pfd)))
  (fsocket:close-poll (simple-rpc-server-pc server))

  nil)

(defun simple-rpc-server-construct (programs &key udp-ports tcp-ports providers)
  (let ((server (make-instance 'simple-rpc-server
                               :programs programs
                               :providers providers)))
    (setf (simple-rpc-server-exiting server) nil)

    (handler-bind ((error (lambda (e)
                            (declare (ignore e))
                            ;; ensure we clear up on early exit, but decline to handle the error 
                            (simple-rpc-server-destruct server)
                            nil)))
      
      ;; allocate the fds and register with pc, also register each program with rpcbind
      (let ((pc (fsocket:open-poll))
            (real-udp-ports nil)
            (real-tcp-ports nil))
        ;; store the poll context here so we can always destroy it later
        (setf (simple-rpc-server-pc server) pc)
        
        (dolist (port udp-ports)
          (let ((fd (fsocket:open-socket :type :datagram)))
            (fsocket:socket-bind fd (fsocket:make-sockaddr-in :port port))
            (fsocket:poll-register pc (make-instance 'udp-pollfd
                                                     :fd fd
                                                     :events (fsocket:poll-events :pollin)))
            
            (push (fsocket:sockaddr-in-port (fsocket:socket-name fd))
                  real-udp-ports)))
        (dolist (port tcp-ports)
          (let ((fd (fsocket:open-socket :type :stream)))
            (fsocket:socket-bind fd (fsocket:make-sockaddr-in :port port))
            (fsocket:socket-listen fd)
            (fsocket:poll-register pc (make-instance 'tcp-listen-pollfd
                                                     :fd fd
                                                     :events (fsocket:poll-events :pollin)))
            (push (fsocket:sockaddr-in-port (fsocket:socket-name fd))
                  real-tcp-ports)))
        
	(with-rpc-client (client udp-client
				 :addr (fsocket:make-sockaddr-in :addr #(127 0 0 1)
								 :port 111)
				 :provider (make-unix-provider))
	  (dolist (program programs)
	    (destructuring-bind (pg vs fn) program
	      (declare (ignore fn))
	      (dolist (port real-udp-ports)
		(unless (= port 111)
		  (call-rpcbind-set client
				    (make-mapping :program pg
						  :version vs
						  :protocol :udp
						  :port port))))
	      (dolist (port real-tcp-ports)
		(unless (= port 111)
		  (call-rpcbind-set client
				    (make-mapping :program pg
						  :version vs
						  :protocol :tcp
						  :port port)))))))))
    
    server))

;; threading, if available
(defun simple-rpc-server-run (server)
  "Loop processing RPC requests until the server exit flag is set."
  (do ()
      ((simple-rpc-server-exiting server))
    (simple-rpc-server-process server)))
  
(defun simple-rpc-server-start (server &optional run name)
  "Start a simple rpc server.
SERVER ::= simple-rpc-server instance.
RUN ::= an entry point function. If not supplied SIMPLE-RPC-SERVER-RUN is used.
NAME ::= a string to use as the thread name.
"
  (setf (simple-rpc-server-thread server)
        (bt:make-thread (lambda () (if run
                                       (funcall run server)
                                       (simple-rpc-server-run server)))
                        :name (or name "simple-rpc-server")))
  server)

(defun simple-rpc-server-stop (server)
  "Stop a simple rpc server thread."
  (setf (simple-rpc-server-exiting server) t)
  (bt:join-thread (simple-rpc-server-thread server))
  (setf (simple-rpc-server-exiting server) nil
        (simple-rpc-server-thread server) nil)
  nil)
