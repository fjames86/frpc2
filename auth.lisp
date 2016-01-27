;;;; Copyright (c) Frank James 2016 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.


(in-package #:frpc2)

(defconstant +max-opaque-auth+ 400)
(defun make-auth-block (&optional (count +max-opaque-auth+))
  (make-xdr-block :buffer (make-array count
                                      :initial-element 0
                                      :element-type '(unsigned-byte 8))
                  :count count))

;; for the client 
(defclass client-provider ()
  ())
(defgeneric client-authenticate (provider msg)
  (:documentation "Generate auth and verf blocks for the call. Returns (values auth verf)."))

(defmethod client-authenticate ((p client-provider) msg)
  (declare (ignore msg))
  (values (make-opaque-auth) (make-opaque-auth)))

(defgeneric client-verify (provider verf)
  (:documentation "Process the verf received from the server. If control passes
through then the call was verified. If the verifier was invalid then the 
provider should signal a condition here."))

(defmethod client-verify ((p client-provider) verf)
  (declare (ignore verf))
  nil)

;; for the server
(defclass server-provider ()
  ())

(defgeneric server-authenticate (provider auth verf msg blk)
  (:documentation "Server authentication provider interface. 
AUTH, VERF ::= the auth and verf blocks provided by the client.
MSG, BLK ::= the call msg and argument block. Most providers can ignore these,
but some providers need to inspect and possibly modify the arguments.

The provider may signal a condition, including ACCEPT-ERROR, to prevent control 
passing to the standard procedure handler.

Returns (values verf context) where verf is the verifier to reply with 
and context is a custom value the provider may generate to tag the call. Handlers
may use this to query the provider for information about the call authentication. Providers should offer an API to consume this for handlers."))

;; We define a default method which returns nil 
(defmethod server-authenticate ((p server-provider) auth verf msg blk)
  (declare (ignore auth verf msg blk))
  nil)

(defun authenticate-rpc-call (msg providers blk)
  (declare (type rpc-msg msg))
  (let* ((body (rpc-call-body msg))
         (auth (call-body-auth body))
         (verf (call-body-verf body)))
         
    ;; authenticate    
    (do ((pvs providers (cdr pvs))
	 (rv nil)
	 (pv nil)
	 (rcxt nil))
	((or rv (null pvs))
	 (values (or rv (make-opaque-auth))
		 pv
		 rcxt))
      (multiple-value-bind (v cxt) (server-authenticate (car pvs)
							auth verf
							msg blk)
	(when v
	  (setf rv v
		pv (car pvs)
		rcxt cxt))))))


;; Some authentication flavours require encrypting the call args/results
;; This requires us to provide an API for providesr to modify the packed data.

(defgeneric client-modify-call (provider blk start end)
  (:documentation "Allow the client provider to modify the contents of the block."))

(defmethod client-modify-call ((provider t) blk start end)
  (declare (ignore blk start end))
  nil)

(defgeneric client-modify-reply (provider blk start end)
  (:documentation "Allow the provider to modify the contents of the block."))

(defmethod client-modify-reply ((provider t) blk start end)
  (declare (ignore blk start end))
  nil)



(defgeneric server-modify-call (provider cxt blk start end)
  (:documentation "Allow the server provider to modify the contents of the block."))

(defmethod server-modify-call ((provider t) cxt blk start end)
  (declare (ignore blk start end))
  nil)

(defgeneric server-modify-reply (provider cxt blk start end)
  (:documentation "Allow the server provider to modify the contents of the block."))

(defmethod server-modify-reply ((provider t) cxt blk start end)
  (declare (ignore cxt blk start end))
  nil)


;; ------------------------------------------------------
;; ------------------------------------------------------

;; AUTH_UNIX/AUTH_SHORT
(defxarray uint32-array ((:mode :list))
  :uint32)

(defxstruct unix ()
  (stamp :uint32)
  (name :string)
  (uid :uint32)
  (gid :uint32)
  (gids uint32-array))

(defclass unix-client-provider (client-provider)
  ((unix :initarg :unix :reader unix-provider-unix)
   (nickname :initform nil :accessor unix-provider-nickname)))

(defmethod print-object ((p unix-client-provider) stream)
  (print-unreadable-object (p stream :type t)
    (format stream ":NICKNAME ~A" (unix-provider-nickname p))))

(defmethod reinitialize-instance :after ((p unix-client-provider) &rest initargs &key &allow-other-keys)
  (declare (ignore initargs))
  (setf (unix-provider-nickname p) nil))

(defmethod client-authenticate ((provider unix-client-provider) msg)
  (declare (ignore msg))
  
  ;; generate the auth and verf
  (let ((nickname (unix-provider-nickname provider)))
    (values 
     (cond
       (nickname
        (let ((blk (make-auth-block 4)))
          (encode-uint32 blk nickname)
          (make-opaque-auth :flavour :auth-short
                            :data (list (xdr-block-buffer blk) 0 (xdr-block-offset blk)))))
       (t
        (let ((blk (make-auth-block)))
          (encode-unix blk (unix-provider-unix provider))
          (make-opaque-auth :flavour :auth-unix
                            :data (list (xdr-block-buffer blk) 0 (xdr-block-offset blk))))))
     (make-opaque-auth))))

(defmethod client-verify ((p unix-client-provider) verf)
  (when (eq (opaque-auth-flavour verf) :auth-short)
    (destructuring-bind (buffer start end) (opaque-auth-data verf)
      (let ((blk (make-xdr-block :buffer buffer :offset start :count end)))
        (let ((nickname (decode-uint32 blk)))
          (setf (unix-provider-nickname p) nickname)))))
  nil)

(defun make-unix-provider (&key name timestamp (uid 0) (gid 0) gids)
  "Allocate a client AUTH_UNIX provider.
NAME ::= the machine name.
TIMESTAMP ::= current unix timestamp.
UID ::= user ID
GID ::= group ID
GIDS ::= list of groups IDs.

Returns a new client unix provider."
  (make-instance 'unix-client-provider
		 :unix (make-unix :name (or name (machine-instance))
				  :stamp (or timestamp
					     (- (get-universal-time)
						(encode-universal-time 0 0 0 1 1 1970 0)))
				  :uid uid
				  :gid gid
				  :gids gids)))

(defclass unix-server-provider (server-provider)
  ((contexts :initform (make-list 16) :reader unix-provider-contexts)))

(defmethod server-authenticate ((p unix-server-provider) auth verf msg blk)
  (declare (ignore verf msg blk))
  (destructuring-bind (buffer start end) (opaque-auth-data auth)
    (case (opaque-auth-flavour auth)
      (:auth-unix
       (let* ((blk (make-xdr-block :buffer buffer :offset start :count end))
	      (unix (decode-unix blk))
	      (nickname (random #xffffffff))
	      (now (get-universal-time))
	      (oldest 0)
	      (cxt nil))
	 ;; find an empty slot
	 (do ((contexts (unix-provider-contexts p) (cdr contexts))
	      (i 0 (1+ i))
	      (age 0))
	     ((null contexts))
	   (let ((context (car contexts)))
	     (cond
	       ((null context)
		(setf oldest i
		      contexts nil))
	       (t 
		(destructuring-bind (cunix cnickname cage) context
		  (declare (ignore cunix cnickname))
		  (when (or (zerop age) (< cage age))
		    ;; we have found an older entry
		    (setf age cage
			  oldest i)))))))
	 ;; fill in the oldest entry
	 (setf cxt (list unix nickname now)
	       (nth oldest (unix-provider-contexts p)) cxt)
	   
	 ;; return the reply verf
	 (let ((rblk (make-auth-block 4)))
	   (encode-uint32 rblk nickname)
	   
	   (values 
	    (make-opaque-auth :flavour :auth-short
			      :data (list (xdr-block-buffer rblk) 0 (xdr-block-offset rblk)))
	    cxt))))
      (:auth-short 
       (let ((blk (make-xdr-block :buffer buffer :offset start :count end)))
	 (let ((nickname (decode-uint32 blk)))
	   ;; find the context or fail
	   (let ((cxt (find-if (lambda (c)
				 (when c 
				   (= (third c) nickname)))
			       (unix-provider-contexts p))))
	     (unless cxt
	       (error 'auth-error :stat :badcred))
	     
	     ;; update the timestamp
	     (setf (third cxt) (get-universal-time))
	     
	     ;; return the reply verf
	     (let ((rblk (make-auth-block 4)))
	       (encode-uint32 rblk nickname)
	       (values 
		(make-opaque-auth :flavour :auth-short
				  :data (list (xdr-block-buffer rblk) 0 (xdr-block-offset rblk)))
		cxt)))))))))
  
        
            
;; --------------------------------------------
