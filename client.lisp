;;;; Copyright (c) Frank James 2016 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(in-package #:frpc2)

;; we want a funciton which will encode a call and decode a reply
(declaim (ftype (function (xdr-block (or function symbol) * integer integer integer
				     &key (:provider (or null client-provider)) (:xid (or null integer)))
			  integer)
		encode-rpc-call))
(defun encode-rpc-call (blk arg-encoder arg program version proc &key provider xid)
  "Encode an RPC call message into the block.
BLK ::= the XDR block
ARG-ENCODER ::= function specifying an XDR encoder 
ARG ::= value to pass to ARG-ENCODER 
PROGRAM, VERSION, PROC ::= integers specifying the procedure to call
PROVIDER ::= instance of CLIENT-PROVIDER. If not supplied then AUTH_NULL is assumed.
XID ::= transaction ID for the call. If not supplied a random XID is generated.

Returns the XID for the call."
  (declare (type xdr-block blk)
	   (type (or function symbol) arg-encoder)
	   (type t arg)
	   (type integer program version proc)
	   (type (or null client-provider) provider)
	   (type (or null integer) xid))
  ;; generate the msg first without the auth/verf so we can pass it into the
  ;; client provider, incase it needs to have access to it
  (let ((msg (make-rpc-call program version proc
			    :xid xid)))
    (multiple-value-bind (auth verf)
	(if provider
	    (client-authenticate provider msg)
	    (values (make-opaque-auth) (make-opaque-auth)))
      ;; set the auth/verf slots in the msg
      (setf (call-body-auth (xunion-val (rpc-msg-body msg)))
	    auth
	    (call-body-verf (xunion-val (rpc-msg-body msg)))
	    verf)
      ;; encode into xdr 
      (encode-rpc-msg blk msg)
      (let ((start (xdr-block-offset blk)))
	(funcall arg-encoder blk arg)
	(let ((end (xdr-block-offset blk)))
	  ;; allow the provider to modify the call arg
	  (when provider 
	    (client-modify-call provider blk start end))))
      (rpc-msg-xid msg))))

(declaim (ftype (function (xdr-block (or function symbol) integer (or null client-provider) &optional (or null rpc-msg))
			  *)
		decode-rpc-reply))
(defun decode-rpc-reply (blk res-decoder xid provider &optional message)
  "Decode and process an RPC reply message.
BLK ::= XDR block containing the message and data.
RES-DECODER ::= function specifying an XDR decoder function.
XID ::= the transaction ID expected in the reply. An error will be signalled if the XID of 
the message does not match the one expected.
PROVIDER ::= instance of CLIENT-PROVIDER or nil.
MESSAGE ::= if suppled, it is assumed the message has already been decoded from the block.

Returns the result decoded by RES-DECODER."
  (declare (type xdr-block blk)
	   (type (or function symbol) res-decoder)
	   (type integer xid)
	   (type (or null client-provider) provider)
	   (type (or null rpc-msg) message))
  (let ((rmsg (or message (decode-rpc-msg blk))))
    ;; check this reply corresponds to the call
    (unless (= (rpc-msg-xid rmsg) xid)
      (error 'xdr-error :format-string "XID mismatch"))
    
    ;; verify the server
    (let ((verf (rpc-reply-verf rmsg)))
      (when provider 
        (client-verify provider verf)))

    ;; allow the provider to modify the result 
    (client-modify-reply provider
			 blk
			 (xdr-block-offset blk)
			 (xdr-block-count blk))
    
    (funcall res-decoder blk)))

;; base class for RPC clients 
(defclass rpc-client ()
  ((blk :initform (xdr-block (* 1024 32)) :initarg :block :accessor rpc-client-block)
   (outstanding :initform nil :accessor rpc-client-outstanding)
   (provider :initform nil :initarg :provider :accessor rpc-client-provider)))

(defmethod print-object ((c rpc-client) stream)
  (print-unreadable-object (c stream :type t)))

(defgeneric rpc-client-close (client)
  (:documentation "Free all resources."))

(defmacro with-rpc-client ((var class-name &rest initargs) &body body)
  `(let ((,var (make-instance ',class-name ,@initargs)))
     (unwind-protect (progn ,@body)
       (rpc-client-close ,var))))

(defgeneric rpc-client-call (client arg-encoder arg res-decoder program version proc)
  (:documentation "Execute an RPC and await a reply. Returns the result of the call."))

(declaim (ftype (function (rpc-client (or function symbol) * (or function symbol) integer integer integer)
			  *)
		rpc-call))
(defun call-rpc (client arg-encoder arg res-decoder program version proc)
  "Perform a synchronous RPC call and wait for a reply.
CLIENT ::= instance of RPC-CLIENT.
ARG-ENCODER ::= a DrX XDR encoder for the procedure argument.
ARG ::= the argument.
RES-DECODER ::= a DrX decoder for the procedure result.
PROGRAM, VERSION, PROC ::= the integers specifying the procedure.

Blocks until a reply is received. Returns the procedure result."
  (declare (type rpc-client client)
	   (type (or function symbol) arg-encoder res-decoder)
	   (type t arg)
	   (type integer program version proc))
  (rpc-client-call client arg-encoder arg res-decoder program version proc))
    
(defgeneric rpc-client-send (client)
  (:documentation "Send the client block and return immediately."))

(declaim (ftype (function (rpc-client (or function symbol) * (or function symbol) integer integer integer)
			  integer)
		send-rpc))
(defun send-rpc (client arg-encoder arg res-decoder program version proc)
  "Send an RPC call message and return immediately. Parameters as for CALL-RPC.

CLIENT ::= RPC-CLIENT instance.

Returns a transaction ID integer (XID). This should be used to pair up 
procedure results returned from RECV-RPC."
  (declare (type rpc-client client)
	   (type (or function symbol) arg-encoder res-decoder)
	   (type t arg)
	   (type integer program version proc))
  ;; encode the call into the client block
  (let ((blk (rpc-client-block client)))
    (let ((xid (encode-rpc-call blk
				arg-encoder arg
				program version proc
				:provider (rpc-client-provider client))))
      ;; push onto the outstanding list
      (push (list xid res-decoder)
	    (rpc-client-outstanding client))
	    
      ;; call the send routine to do the transport 
      (rpc-client-send client)

      xid)))
	    

(defgeneric rpc-client-recv (client)
  (:documentation "Receive an RPC reply into the client block."))

(defun pop-client-outstanding (client xid)
  (do ((outs (rpc-client-outstanding client) (cdr outs))
       (prev nil)
       (out nil))
      ((or (null outs) out) out)
    (when (= (car (car outs)) xid)
      (setf out (car outs))
      (if prev
	  (setf (cdr prev) (cdr outs))
	  (setf (rpc-client-outstanding client)
		(cdr (rpc-client-outstanding client)))))
    (setf prev outs)))

(declaim (ftype (function (rpc-client) (values * integer)) recv-rpc))
(defun recv-rpc (client)
  "Receive an RPC reply message. Will block until a reply is received. 

CLIENT ::= RPC-CLIENT instance.

Returns (values result xid)."
  (declare (type rpc-client client))
  ;; either returns successfully then the block has been filled or errors
  (rpc-client-recv client)
  ;; process the contents of the block 
  (let* ((blk (rpc-client-block client))
	 (rmsg (decode-rpc-msg blk)))
    (let ((out (pop-client-outstanding client (rpc-msg-xid rmsg))))
      (unless out
	(error 'rpc-error
	       :msg (format nil "Unexpected XID ~A" (rpc-msg-xid rmsg))))
      (values 
       (decode-rpc-reply blk (second out) (rpc-msg-xid rmsg)
			 (rpc-client-provider client)
			 rmsg)
       (rpc-msg-xid rmsg)))))
      
  
;; -------------------------------

;; some simple example clients which use UDP and TCP for transport 
(defclass udp-client (rpc-client)
  ((addr :initarg :addr
	 :initform (fsocket:make-sockaddr-in :addr #(127 0 0 1) :port 111)
	 :accessor udp-client-addr)
   (fd :initarg :fd :initform nil :accessor udp-client-fd)
   (pc :initarg :pc :initform nil :accessor udp-client-pc)
   (retry :initform 2 :initarg :retry :accessor udp-client-retry)
   (timeout :initform 500 :initarg :timeout :accessor udp-client-timeout)))

(defmethod print-object ((u udp-client) stream)
  (print-unreadable-object (u stream :type t)
    (format stream ":ADDR ~A" (udp-client-addr u))))

(defmethod initialize-instance :after ((u udp-client) &rest initargs &key &allow-other-keys)
  (declare (ignore initargs))
  (unless (udp-client-fd u)
    (setf (udp-client-fd u) (fsocket:open-socket :type :datagram))
    (fsocket:socket-bind (udp-client-fd u) (fsocket:make-sockaddr-in)))
  
  (unless (udp-client-pc u)
    (setf (udp-client-pc u) (fsocket:open-poll))
    (fsocket:poll-register (udp-client-pc u)
                           (make-instance 'fsocket:pollfd
                                          :fd (udp-client-fd u)
                                          :events (fsocket:poll-events :pollin)))))

(defmethod rpc-client-close ((u udp-client))
  (when (udp-client-fd u) (fsocket:close-socket (udp-client-fd u)))
  (when (udp-client-pc u) (fsocket:close-poll (udp-client-pc u))))

(defmethod rpc-client-send ((u udp-client))
  (let ((blk (rpc-client-block u)))
    (fsocket:socket-sendto (udp-client-fd u)
			   (xdr-block-buffer blk)
			   (udp-client-addr u)
			   :start 0
			   :end (xdr-block-offset blk))))

(defmethod rpc-client-recv ((u udp-client))
  (let ((blk (rpc-client-block u)))
    (when (udp-client-timeout u)
      (unless (fsocket:poll (udp-client-pc u) :timeout (udp-client-timeout u))
	(error 'rpc-timeout-error))
      (multiple-value-bind (count raddr) (fsocket:socket-recvfrom (udp-client-fd u) (xdr-block-buffer blk))
	(setf (udp-client-addr u) raddr
	      (xdr-block-offset blk) 0
	      (xdr-block-count blk) count)))))

;; we try sending the message until we get a response or run out of retries
;; each subsequent retry increases the timeout by a factor of 1.5, a number I chose at random
(defmethod rpc-client-call ((u udp-client) arg-encoder arg res-decoder program version proc)
  (do ((n (udp-client-retry u) (1- n))
       (timeout (udp-client-timeout u) (truncate (* timeout 1.5)))
       (blk (rpc-client-block u))
       (provider (rpc-client-provider u))
       (done nil)
       (res nil))
      ((or done (zerop n))
       (if done 
	   res
	   (error 'rpc-timeout-error)))
    ;; encode the message and send it
    (reset-xdr-block blk)
    (let ((xid (encode-rpc-call blk arg-encoder arg 
				program version proc
				:provider provider)))
      (fsocket:socket-sendto (udp-client-fd u)
			     (xdr-block-buffer blk)
			     (udp-client-addr u)
			     :start 0
			     :end (xdr-block-offset blk))
      ;; wait for reply 
      (when (udp-client-timeout u)
	(cond
	  ((fsocket:poll (udp-client-pc u) :timeout timeout)
	   (multiple-value-bind (count raddr) (fsocket:socket-recvfrom (udp-client-fd u) (xdr-block-buffer blk))
	     (setf (udp-client-addr u) raddr
		   (xdr-block-offset blk) 0
		   (xdr-block-count blk) count
		   res (decode-rpc-reply blk res-decoder xid 
					 (rpc-client-provider u))
		   done t)))
	  (t 
	   ;; timeout, ... don't need to do anything here
	   nil))))))

;; -------------------------------------------------------

(defclass tcp-client (rpc-client)
  ((fd :initform nil :accessor tcp-client-fd)
   (pc :initform nil :accessor tcp-client-pc)
   (addr :initarg :addr :reader tcp-client-addr)
   (timeout :initform 1000 :initarg :timeout :accessor tcp-client-timeout)))

(defmethod initialize-instance :after ((tcp tcp-client) &rest initargs &key &allow-other-keys)
  (declare (ignore initargs))
  (handler-bind ((error (lambda (c)
                          (declare (ignore c))
                          ;; close the socket and poll context but decline to handle the error
                          (when (tcp-client-fd tcp)
                            (fsocket:close-socket (tcp-client-fd tcp)))
                          (when (tcp-client-pc tcp)
                            (fsocket:close-poll (tcp-client-pc tcp)))
                          nil)))
    (setf (tcp-client-fd tcp) (fsocket:open-socket :type :stream))
    (fsocket:socket-bind (tcp-client-fd tcp) (fsocket:make-sockaddr-in))
    (setf (tcp-client-pc tcp) (fsocket:open-poll))
    ;; Issue the connect before registering with the poll context.
    ;; This is because on Windows once you register with the poll context
    ;; (which underneath calls WSAEventSelect) the socket is converted
    ;; to a non-blocking socket and the connect will operate in non-blocking
    ;; mode, which we don't actually want.
    (fsocket:socket-connect (tcp-client-fd tcp)
                            (tcp-client-addr tcp))
    (fsocket:poll-register (tcp-client-pc tcp)
			   (make-instance 'fsocket:pollfd
					  :fd (tcp-client-fd tcp)
					  :events (fsocket:poll-events :pollin)))))


(defmethod rpc-client-close ((tcp tcp-client))
  (fsocket:socket-shutdown (tcp-client-fd tcp) :both)
  (fsocket:close-socket (tcp-client-fd tcp))
  (fsocket:close-poll (tcp-client-pc tcp)))

(defun rpc-client-safe-poll (tcp)
  (do ((done nil))
      (done)
    (let ((pfds (fsocket:poll (tcp-client-pc tcp)
			      :timeout (tcp-client-timeout tcp))))
      (cond
	(pfds
	 (let ((revts (fsocket:poll-events (fsocket:pollfd-revents (car pfds)))))
	   (when revts (setf done t))))
	(t
	 (error 'rpc-timeout-error))))))

(defmethod rpc-client-call ((tcp tcp-client) arg-encoder arg res-decoder program version proc)
  ;; start by encoding the message
  (reset-xdr-block (rpc-client-block tcp))
  (let* ((blk (rpc-client-block tcp))
	 (xid (encode-rpc-call blk arg-encoder arg 
			       program version proc
			       :provider (rpc-client-provider tcp)))
	 (cblk (make-auth-block 4)))

    ;; we need to send a fragment count first with the terminal bit set
    (encode-uint32 cblk (logior (xdr-block-offset blk) #x80000000))
    ;; TODO: check for a short write 
    (let ((cnt (fsocket:socket-send (tcp-client-fd tcp) (xdr-block-buffer cblk))))
      (unless (= cnt 4) (error "Short write")))
    
    ;; send the fragment payload.
    ;; TODO: check for short write 
    (let ((cnt (fsocket:socket-send (tcp-client-fd tcp) (xdr-block-buffer blk)
				    :start 0 :end (xdr-block-offset blk))))
      (unless (= cnt (xdr-block-offset blk)) (error "Short write")))
	    
    (let ((start 0))
      (flet ((recv-fragment-count ()
	       ;; Read the fragment header which is a 4-octet BE uint32. If the high bit (0x80000000) is
	       ;; set then this indicates it is the final fragment.
	       (setf (xdr-block-offset cblk) 0)
	       (rpc-client-safe-poll tcp)

	       ;; TODO: check for a short read 
	       (let ((cnt (fsocket:socket-recv (tcp-client-fd tcp) (xdr-block-buffer cblk))))
		 (when (zerop cnt) (error 'rpc-error :msg "Graceful close")))
	       (setf (xdr-block-offset cblk) 0)
	       (decode-uint32 cblk))
	     (recv-fragment (count)
	       ;; This function keeps reading until COUNT bytes have been received
	       (do ((cnt 0))
		   ((>= cnt count) cnt)
		 (rpc-client-safe-poll tcp)

		 ;; check there is enough space in buffer to actually read into
		 (unless (>= (- (length (xdr-block-buffer blk)) start) count)
		   ;; TODO: signal a better error condition 
		   (error 'rpc-error :msg "Short buffer"))
		 (let ((c (fsocket:socket-recv (tcp-client-fd tcp) (xdr-block-buffer blk)
					       :start start)))
		   (when (zerop c) (error 'rpc-error :msg "Graceful close"))
		   (incf cnt c)
		   (incf start c)))))
	
	;; We keep looping until the final fragment has been read
	(do ((cnt 0)
	     (done nil))
	    (done (setf (xdr-block-count blk) cnt
			(xdr-block-offset blk) 0))
	  (let* ((rcount (recv-fragment-count))
		 (last-p (not (zerop (logand rcount #x80000000))))
		 (count (logand rcount (lognot #x80000000))))
	    ;; read the fragement 
	    (recv-fragment count)
	    (incf cnt count)
	    (when last-p (setf done t))))))

    (decode-rpc-reply blk res-decoder xid
		      (rpc-client-provider tcp))))
    

;; ------------------------------------------------------

(defclass broadcast-client (udp-client)
  ())

(defmethod initialize-instance :after ((c broadcast-client) &rest initargs &key &allow-other-keys)
  (declare (ignore initargs))
  ;; set the socket option
  (setf (fsocket:socket-option (udp-client-fd c) :socket :broadcast) t)
  (unless (udp-client-addr c)
    (setf (udp-client-addr c) (fsocket:make-sockaddr-in :addr #(255 255 255 255)
							:port 111))))

(defmethod rpc-client-call ((c broadcast-client) arg-encoder arg res-decoder program version proc)
  (let ((blk (rpc-client-block c)))
    ;; encode message and broadcast
    (reset-xdr-block blk)
    (let ((xid (encode-rpc-call blk arg-encoder arg 
				program version proc
				:provider (rpc-client-provider c))))
      (fsocket:socket-sendto (udp-client-fd c)
			     (xdr-block-buffer blk)
			     (udp-client-addr c)
			     :start 0
			     :end (xdr-block-offset blk))
      (when (udp-client-timeout c)
	(do ((done nil)
	     (results nil))
	    (done results)
	  (cond
	    ((fsocket:poll (udp-client-pc c) 
			   :timeout (udp-client-timeout c))
	     (multiple-value-bind (count raddr) (fsocket:socket-recvfrom (udp-client-fd c) (xdr-block-buffer blk))
	       (setf (udp-client-addr c) raddr
		     (xdr-block-offset blk) 0
		     (xdr-block-count blk) count)
	       (push (list raddr
			   (decode-rpc-reply blk res-decoder xid
					     (rpc-client-provider c)))
		     results)))
	    (t (setf done t))))))))

  
;; ---------------------------------------------------

;; macro sugar to define an interface of client calls

;; what we want is to expand a form like
;; (define-rpc-interface rpcbind (100000 2)
;;   (null :void :void))
;; to
;; (defun call-rpcbind-null (client)
;;   (call-rpc client #'encode-void nil #'decode-void
;;             100000 2 0))

(defmacro defrpc (name (program version proc) arg-type res-type)
  "Define a function which dispatches to CALL-RPC. 
NAME ::= name of function to define.
PROGRAM, VERSION, PROC ::= integers specifying the procedure.
ARG-TYPE, RES-TYPE ::= symbols naming DrX XDR types."
  `(defun ,name (client ,@(unless (eq arg-type :void)
				  (list (drx::symbolicate arg-type))))
     (call-rpc client
	       (function ,(drx:generate-encoder-name arg-type))
	       ,(if (eq arg-type :void)
		    nil
		    (drx::symbolicate arg-type))
	       (function ,(drx:generate-decoder-name res-type))
	       ,program ,version ,proc)))
  

(defmacro define-rpc-client (name (program version &rest options) &rest rpcs)
  `(progn
     ;; defining the client calls
     ,@(let ((proc 0))
	    (mapcar (lambda (rpc)
		      (destructuring-bind (rpc-name arg-type res-type &rest roptions) rpc
			(declare (ignore roptions))
			(prog1
			    `(defrpc ,(drx::symbolicate (or (cadr (assoc :prefix options)) 'call-)
						       name
						       '-
						       rpc-name)
				 (,program ,version ,proc) ,arg-type ,res-type)
			  (incf proc))))
		    rpcs))))

(defmacro define-rpc-server (name (program version &rest options) &rest rpcs)
  `(defun ,(drx::symbolicate 'make- name '-program) ()
     (list ,program ,version 
	   (list ,@(mapcan (lambda (rpc)
			     (destructuring-bind (rpc-name arg-type res-type &rest roptions) rpc
			       (declare (ignore roptions))
			       (list `(list (function ,(drx::symbolicate (or (cadr (assoc :prefix options)) 'handle-)
									 name
									 '-
									 rpc-name))
					    (function ,(drx:generate-decoder-name arg-type))
					    (function ,(drx:generate-encoder-name res-type))))))
			   rpcs)))))

  
(defmacro define-rpc-interface (name (program version &rest options) &rest rpcs)
  "Define a set of client functions to call the RPCs with the specified program and version.

NAME ::= name of the interface.
PROGRAM, VERSION ::= integer specifiers for the program and version of this interface. Note that 
these should be constants at compile time, i.e. either immediate integers or symbols naming constants. 

RPCS ::= {RPC-SPEC}*
RPC-SPEC ::= (proc-name arg-type res-type)
PROC-NAME ::= name of the procedure
ARG-TYPE, RES-TYPE ::= symbols naming the XDR types. See the DrX documentation for how to define these.
OPTIONS ::= {PROC-OPTION}*
PROC-OPTIONS ::= (:documentation docustring)

The function generated for each procedure is by default CALL-(NAME)-(PROC-NAME), this can be changed 
by providing a :NAME proc-option. 

The ARG-TYPE and RES-TYPE types must have already been defined when this macro expands to ensure the encoders
and decoders have been defined. Note that only the arg encoder and res decoder are required.
"
  `(progn
     (define-rpc-client ,name (,program ,version ,@options) ,@rpcs)
     (define-rpc-server ,name (,program ,version ,@options) ,@rpcs)))

(defmacro declare-rpc-interface (name (program version) &rest rpcs)
  "Declare the existence of an RPC interface, but don't actually define it yet.
 This defines a macro DEFINE-<name>-INTERFACE which can be used to define 
clients and servers at a later state. 
This is useful for servers which put their handler functions in a separate file
to the client interface. You can declare it first and define the client and 
server separately."
  `(progn
     (defmacro ,(drx::symbolicate 'define- name '-client) (&rest options)
       `(define-rpc-client ,',name (,',program ,',version ,@options) ,@',rpcs))
     (defmacro ,(drx::symbolicate 'define- name '-server) (&rest options)
       `(define-rpc-server ,',name (,',program ,',version ,@options) ,@',rpcs))))
