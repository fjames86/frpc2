;;;; Copyright (c) Frank James 2016 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

;;; Brief:
;;; This file defines an authentication provider for the RPCSEC_GSS flavour.
;;; Requirements:
;;; GSS support is provided by the Glass package.
;;; The only GSS provider that has been tested is Cerberus which provides
;;; Kerberos v5 support. In principle, NTLM and spnego flavours should also
;;; work, but would require some extra typing here (see below).
;;; Pitfals:
;;; 1. Only Kerberos has been tested, which only requires a single exchange
;;; to setup the context. Other GSS systems require several exchanges to complete
;;; the handshake and finialize the GSS context. They WILL NOT WORK yet.
;;; 2. We don't validate the verifiers either in the server or client 
;;; 3. Although it's all internally consistent it's never been tested with
;;; another implementation.
;;; 4. There's no way of calling the :destroy proc to close the session
;;; once we're done with it. This doesn't really affect us much though.
;;;
;;; NOTE: This has been typed in by following RFC2203. Although it is internally
;;; consistent (so an frpc2 client will talk to an frpc2 server), it has never
;;; been tried against a different implementation. It is VERY likely there are
;;; bugs or places where it doesn't conform to the spec. 

(defpackage #:frpc2.gss
  (:use #:cl #:frpc2)
  (:export #:make-gss-client-provider
	   #:destroy-gss-client-provider
	   #:gss-server-provider))

(in-package #:frpc2.gss)

(drx:defxenum gss-proc-t ()
  (:data 0)
  (:init 1)
  (:continue 2) ;; GSS_CONTINUE_INIT if multiple exchanges required 
  (:destroy 3))

(drx:defxenum gss-service-t ()
  (:none 1)
  (:integrity 2)
  (:privacy 3))

(defconstant +gss-version+ 1)

;; this is defined as a union(version) but since there is only a single permitted version (1) 
;; lets just put it in a structure
(drx:defxstruct gss-cred ()
  (version :uint32 +gss-version+)
  (proc gss-proc-t)
  (seqno :uint32)
  (service gss-service-t)
  (handle :opaque))

;; the arguments sent as a part of the control message (to the nullproc)
(drx:defxtype gss-init-arg () :opaque)

(drx:defxstruct gss-init-res ()
  (handle :opaque)
  (major-stat :uint32 0)
  (minor-stat :uint32 0)
  (seq-window :uint32 10)
  (token :opaque))

;; this is sent in place of the arguments if the service level is :integrity
(drx:defxstruct gss-integ-data ()
  (integ :opaque) ;; packed gss-data-t 
  (checksum :opaque)) ;; computed using GSS_GetMIC(integ) or equivalent

;; this is packed and placed in the integ field of the gss-integ-data structure
;;(defxstruct gss-data-t ()
;;  (seqno :uint32)
;;  (arg proc-req-arg-t)) ;; here the argument type is whatever the normal argument type is

;; this is sent in place of the arguments if the service level is :privacy
;; In this case, the arguments have been encrypted using GSS wrap() call or equivalent
(drx:defxtype gss-priv-data () :opaque)

;; (drx:defxenum gss-major-stat ()
;;   (:complete #x00000000)
;;   (:continue-needed #x00000001)
;;   (:duplicate-token #x00000002)
;;   (:old-token #x00000004)
;;   (:unseq-token #x00000008)
;;   (:gap-token #x00000010)
;;   (:bad-mech #x00010000)
;;   (:bad-name #x00020000)
;;   (:bad-nametype #x00030000)
;;   (:bad-bindings #x00040000)
;;   (:bad-status #x00050000)
;;   (:bad-mic #x00060000)
;;   (:bad-sig #x00060000)
;;   (:no-cred #x00070000)
;;   (:no-context #x00080000)
;;   (:defective-token #x00090000)
;;   (:defective-credential #x000A0000)
;;   (:credentials-expired #x000B0000)
;;   (:context-expired #x000C0000)
;;   (:failure #x000D0000)
;;   (:bad-qop #x000E0000)
;;   (:unauthorized #x000F0000)
;;   (:unavailable #x00100000)
;;   (:duplicate-element #x00110000)
;;   (:name-not-mn #x00120000)
;;   (:call-inaccessible-read #x01000000)
;;   (:call-inaccessible-write #x02000000)
;;   (:call-bad-structure #x03000000))

;; These are new auth-stats to be returned when signalling an AUTH-ERROR.
(defconstant +gss-cred-problem+ 13)
(defconstant +gss-context-problem+ 14)


;; TODO: the client verifier is NOT empty. See section 5.3.1:
;; QUOTE:
;; The verifier has the opaque_auth structure described earlier.  The
;; flavor field is set to RPCSEC_GSS.  The body field is set as follows.
;; The checksum of the RPC header (up to and including the credential)
;; is computed using the GSS_GetMIC() call with the desired QOP.  This
;; returns the checksum as an opaque octet stream and its length.  This
;; is encoded into the body field. 
;; So computing the verifier is difficult. It requires encoding the RPC header
;; up to the auth block (i.e. not including the verf block). Then checksum it,
;; END QUOTE
;; So for the init request we carry on not generating a verifier.
;; But for the normal requests the verf struct data should contain a checksum
;; of the rpc header.
;; Sec 5.3.3.2 indicates that for the reply, the server should set the verf
;; to the checksum of the seqno

;; ------------------------------------------------------

;; Client 

;; GSS requires a special initialization step.
;; 1. Call the nullproc (proc 0) of the desired program with an AUTH_GSS auth
;; header and AUTH_NULL verf. The header should contain a GSS-CRED struct
;; with proc :INIT.
;; 2. The call should contain an argument of type GSS-INIT-ARG, even though
;; we are calling the nullproc. This should be intercepted by the server's
;; authentication provider so that we get a reply containing a GSS-INIT-RES.

;; Define the special class to generate these initial auth blocks.
(defclass gss-client-init-provider (client-provider)
  ())

;; TODO: to support multiple exchanges in the initialization phase
;; extra work will be required here to generate :continue type proc msgs.
(defmethod client-authenticate ((p gss-client-init-provider) msg)
  (declare (ignore msg))
  
  (let ((blk (make-auth-block)))
    (encode-gss-cred blk
		     (make-gss-cred :proc :init
				    :seqno 0
				    :service :none))
    (values 
     (make-opaque-auth :flavour :auth-gss
		       :data (list (drx:xdr-block-buffer blk)
				   0
				   (drx:xdr-block-offset blk)))
     (make-opaque-auth))))

(defmethod client-verify ((p gss-client-init-provider) verf)
  (declare (ignore verf))
  nil)

;; TODO: extra work will be required here to support multiple exchanges
;; in the initialization phase.
(defun negotiate-gss-context (addr program version creds)
  "Call the RPC service on ADDR to negotiate a GSS context and handle. 
CREDS ::= GSS credentials as returned from GLASS:ACQUIRE-CREDENTIALS.

Returns (values context handle) where CONTEXT is a GSS context for use with
other functions in the GLASS package, and handle is an opaque array containing
the AUTH_GSS connection handle."
  (declare (type fsocket:sockaddr-in addr)
	   (type integer program version))
  (with-rpc-client (c udp-client
		      :addr addr
		      :provider (make-instance 'gss-client-init-provider))
    (multiple-value-bind (context buffer) (glass:initialize-security-context creds)
      (let ((res 
	     (call-rpc c
		       #'encode-gss-init-arg buffer 
		       #'decode-gss-init-res
		       program
		       version
		       0)))
	(values context 
		(gss-init-res-handle res))))))

;; ---------------------------------------------------------

(defclass gss-client-provider (client-provider)
  ((service :initarg :service :initform :none :accessor gss-provider-service)
   (seqno :initform 0 :accessor gss-provider-seqno)
   (handle :initarg :handle :reader gss-provider-handle)
   (creds :initarg :creds :reader gss-provider-creds)
   (context :initarg :context :reader gss-provider-context)))

(defun make-gss-client-provider (addr program version creds &optional (service :none))
  "Allocate an AUTH_GSS client provider. This function requires initial
communication with the RPC server and can therefore block until the process
completes.

ADDR ::= address of the service to contact.
PROGRAM, VERSION ::= integers specifying the program and version.
CREDS ::= GLASS gss credentials.
SERVICE ::= service level, one of :NONE, :INTEGRITY, :PRIVACY

Returns a GSS-CLIENT-PROVIDER instance."
  (multiple-value-bind (cxt hdl) (negotiate-gss-context addr program version creds)
    (make-instance 'gss-client-provider
		   :service service
		   :handle hdl
		   :creds creds
		   :context cxt)))

(defmethod client-authenticate ((p gss-client-provider) msg)
  ;; we already have been assigned a context handle, generate the auth block
  (incf (gss-provider-seqno p))
  (let ((blk (make-auth-block)))
    (encode-gss-cred blk
		     (make-gss-cred :proc :data
				    :seqno (gss-provider-seqno p)
				    :service (gss-provider-service p)
				    :handle (gss-provider-handle p)))
    ;; the verf should be the checksum of the rpc msg header.
    (let ((ablk (make-auth-block))
	  (auth (make-opaque-auth :flavour :auth-gss
				  :data (list (drx:xdr-block-buffer blk)
					      0
					      (drx:xdr-block-offset blk)))))
      ;; we modify the input msg here but it doesn't really matter,
      ;; it will be modified later anyway
      (setf (call-body-auth (drx:xunion-val (rpc-msg-body msg)))
	    auth
	    (call-body-verf (drx:xunion-val (rpc-msg-body msg)))
	    (make-opaque-auth))
      (encode-rpc-msg ablk msg)
      ;; The xdr encoded has the null verf at the end, this is 8 octets long:
      ;; <flavour:4><data len:4><data:0> so we can subtract 8 to get the
      ;; xdr up to the verf, as required for the gss verf
      (let ((chksum (glass:get-mic (gss-provider-context p)
				   (subseq (drx:xdr-block-buffer ablk)
					   0
					   (- (drx:xdr-block-offset ablk) 8)))))
	(values auth
		(make-opaque-auth :flavour :auth-gss
				  :data (list chksum 0 (length chksum))))))))
  
(defmethod client-verify ((p gss-client-provider) verf)
  (declare (ignore verf))
  ;; the verifier is the chucksum of the seqno encoded in big-endian order
  ;; for the moment we will ignore it
  #+nil(when (eq (opaque-auth-flavour verf) :auth-gss)
    (destructuring-bind (buff start end) (opaque-auth-data verf)
      (let ((ablk (make-auth-block 4)))
	(drx:encode-uint32 ablk (gss-provider-seqno p))
	(unless (glass:verify-mic (gss-provider-context p)
				  (subseq buff start end)
				  ;; compute the chksum we expect 
				  (glass:get-mic (gss-provider-context p)
						 (drx:xdr-block-buffer ablk)))
	  (error "Verification failed"))))))

(defmethod client-modify-call ((p gss-client-provider) blk start end)
  (when (member (gss-provider-service p)
		'(:integrity :privacy))
     ;; If the sevice level is :INTEGRITY we need to wrap the args with a checksum. If it's :PRIVACY we also need to encrypt.
    (let ((arg-data (subseq (drx:xdr-block-buffer blk) start end))
	  ;; ablk needs to hold the original arg, seqno and checksum.
	  ;; an extra 64 octets should suffice 
	  (ablk (make-auth-block (+ (- end start) 64)))
	  (context (gss-provider-context p)))
       
       ;; the integ-data must be the seqno followed by arguments
       (drx:encode-uint32 ablk (gss-provider-seqno p))
       (drx:encode-opaque ablk arg-data)
       
       (let* ((integ-msg (subseq (drx:xdr-block-buffer ablk)
				 0
				 (drx:xdr-block-offset ablk)))
	      (integ (make-gss-integ-data :integ integ-msg
					  :checksum (glass:get-mic context
								   integ-msg))))
	 (case (gss-provider-service p)
	   (:integrity 	 
	    ;; write this into the block
	    (setf (drx:xdr-block-offset blk) start)
	    (encode-gss-integ-data blk integ))
	   (:privacy 
	    ;; If the sevice level is :PRIVACY we also need to encrypt it
	    ;; start by encoding into the tmp block
	    (drx:reset-xdr-block ablk)
	    (encode-gss-integ-data ablk integ)
	    (let ((wbuff (glass:wrap context
				     (subseq (drx:xdr-block-buffer ablk)
					     0
					     (drx:xdr-block-offset ablk)))))

	      ;; write this in place of the original arg
	      (setf (drx:xdr-block-offset blk) start)
	      (encode-gss-priv-data blk wbuff))))))))

(defmethod client-modify-reply ((p gss-client-provider) blk start end)
  (let ((context (gss-provider-context p)))
    ;; when the service level is privacy, the arg is an encrypted gss-integ-data
    ;; lets decrypt and replace it first
    (when (eq (gss-provider-service p) :privacy)
      (let ((ibuff (glass:unwrap context
				 (decode-gss-priv-data blk))))
	;; write this in place of the original arg
	(dotimes (i (length ibuff))
	  (setf (aref (drx:xdr-block-buffer blk) (+ start i))
		(aref ibuff i)))
	(setf (drx:xdr-block-count blk) (+ start (length ibuff))
	      (drx:xdr-block-offset blk) start
	      end (+ start (length ibuff)))))

    ;; when service level is integrity or privacy we expect the arg to be an
    ;; integ-data struct
    (when (member (gss-provider-service p) '(:integrity :privacy))
      (let ((ablk (drx:make-xdr-block :buffer (drx:xdr-block-buffer blk)
				      :offset start
				      :count end)))
	(let ((integ-data (decode-gss-integ-data ablk)))
	  (unless (glass:verify-mic context
				    (gss-integ-data-integ integ-data)
				    (gss-integ-data-checksum integ-data))
	    (error "Invalid checksum"))
	  (setf ablk (drx:make-xdr-block :buffer (gss-integ-data-integ integ-data)
					 :offset 0
					 :count (length (gss-integ-data-integ integ-data))))
	  (unless (= (gss-provider-seqno p)
		     (drx:decode-uint32 ablk))
	    (error "Seqnos don't match"))

	  (let* ((adata (drx:decode-opaque ablk))
		 (len (length adata)))
	    ;; now write the data back into the block
	    (do ((i 0 (1+ i)))
		((= i len))
	    (setf (aref (drx:xdr-block-buffer blk) (+ start i))
		  (aref adata i)))

	    ;; update the block pointers and we are done 
	    (setf (drx:xdr-block-count blk)
		  (+ start len))))))))







(defclass gss-client-destroy-provider (client-provider)
  ((seqno :initarg :seqno :reader gss-provider-seqno)
   (handle :initarg :handle :reader gss-provider-handle)))
  

(defmethod client-authenticate ((p gss-client-destroy-provider) msg)
  (declare (ignore msg))
  
  (let ((blk (make-auth-block)))
    (encode-gss-cred blk
		     (make-gss-cred :proc :destroy
				    :seqno (gss-provider-seqno p)
				    :service :none
				    :handle (gss-provider-handle p)))
    (values 
     (make-opaque-auth :flavour :auth-gss
		       :data (list (drx:xdr-block-buffer blk)
				   0
				   (drx:xdr-block-offset blk)))
     (make-opaque-auth))))

(defmethod client-verify ((p gss-client-destroy-provider) verf)
  (declare (ignore verf))
  nil)

(defun destroy-gss-client-provider (provider addr program version)
  "Request an RPCGSS context to be destroyed. 
PROVIDER ::= GSS-CLIENT-PROVIDER instance.
ADDR ::= address of the host to contact.
PROGRAM, VERSION ::= program and version integers.

There is no requirement to call this once the context is done with 
because servers must cope with clients that go away without warning.
However, if a client successfully calls this then they should be assured the
context has been removed from the server."
  (declare (type gss-client-provider provider)
	   (type fsocket:sockaddr-in addr)
	   (type integer program version))
  (with-rpc-client (c udp-client
		      :addr addr
		      :provider (make-instance 'gss-client-destroy-provider
					       :seqno (gss-provider-seqno provider)
					       :handle (gss-provider-handle provider)))
    (call-rpc c
	      #'drx:encode-void nil
	      #'drx:decode-void
	      program
	      version
	      0)))



;; -----------------------------------------

;; The server needs to do some special things:
;; 1. need to intercept calls to proc 0 with an AUTH_GSS auth block.
;; This is actually a special call intended for us rather than the standard
;; handler. It should carry an argument of type gss-init-arg which contains
;; the GSS token. We need to reply with a gss-init-res which contains the
;; handle.
;; 2. We need to intercept args/results for normal calls if the service level
;; is either integrity or privacy. The real arguments will have been either
;; checksummed or encrypted.



(defstruct gss-context 
  (handle nil)
  (context nil)
  (timestamp 0)
  (seqno 0)
  (seq-window 10)
  (service :none))

(defclass gss-server-provider (server-provider)
  ((contexts :initform (make-list 32) :reader gss-provider-contexts)
   (creds :initarg :creds :accessor gss-provider-creds)))

(defun allocate-gss-context (p gcred)
  (let ((cxt (make-gss-context :handle (concatenate '(vector (unsigned-byte 8))
						    (loop :for i :below 4
						       :collect (random 256)))
			       :timestamp (get-universal-time)
			       :seqno (gss-cred-seqno gcred)
			       :service (gss-cred-service gcred)))
	(oldest 0))
    (do ((cxts (gss-provider-contexts p) (cdr cxts))
	 (i 0 (1+ i))
	 (age nil))
	((null cxts))
      (cond
	((null (car cxts))
	 (setf oldest i
	       cxts nil))
	(t
	 (when (or (null age) (< age (gss-context-timestamp (car cxts))))
	   (setf age (gss-context-timestamp (car cxts))
		 oldest i)))))
    (format t "allocating context ~A~%" (gss-context-handle cxt))
    (setf (nth oldest (gss-provider-contexts p)) cxt)
    (format t "oldest: ~A~%" oldest)
    cxt))

(defun gss-context-by-handle (p handle)
  (format t "finding context ~A~%" handle)
  (find-if (lambda (cxt)
	     (and cxt (equalp (gss-context-handle cxt) handle)))
	   (gss-provider-contexts p)))

(defun delete-gss-context-by-handle (p handle)
  (format t "Delete context ~A~%" handle)
  (do ((cxts (gss-provider-contexts p) (cdr cxts)))
      ((null cxts))
    (when (and (car cxts)
	       (equalp (gss-context-handle (car cxts)) handle))
      (let ((cxt (car cxts)))
	(setf (car cxts) nil)
	(return-from delete-gss-context-by-handle cxt)))))

(defun gss-server-init-context (p gcred msg blk)
  "Intercept a call to the nullproc to setup a gss context."

  ;; 1. the msg MUST be calling the nullproc
  ;; 2. the blk MUST encode a GSS-INIT-ARG struct
  ;; 3. if successful, we reply with a GSS-INIT-RES struct

  (unless (and (eq (drx:xunion-tag (rpc-msg-body msg)) :call)
	       (= (call-body-proc (drx:xunion-val (rpc-msg-body msg)))
		  0))
    (error "Not calling proc 0"))

  (let ((iarg (decode-gss-init-arg blk)))
    (multiple-value-bind (cxt rbuf)
	(glass:accept-security-context (gss-provider-creds p) iarg)
      ;; allocate a gss context and generate result 
      (let* ((gcxt (allocate-gss-context p gcred))
	     (res (make-gss-init-res :handle (gss-context-handle gcxt)
				     :major-stat 0
				     :minor-stat 0
				     :seq-window (gss-context-seq-window gcxt)
				     :token rbuf)))
	(setf (gss-context-context gcxt) cxt)       
	;; signal an early exit
	(rpc-manual-reply blk 
			  (make-rpc-reply (rpc-msg-xid msg) :success)  
			  #'encode-gss-init-res res)))))
			

;; the reply verifier should be a checksum of the seqno used in the call.
;; The call verf should be a checksum of the rpc header not including the verf.
;; TODO: validate the call verf
(defmethod server-authenticate ((p gss-server-provider) auth verf msg blk)
  (declare (ignore verf))
  
  ;; If the nullproc is being called and the gss-cred struct indicates
  ;; proc :INIT then we need to intercept this call and process it separately.
  ;; We can signal an early return by signalling ACCEPT-ERROR :SUCCESS
  (when (eq (opaque-auth-flavour auth) :auth-gss)
    (destructuring-bind (abuf astart aend) (opaque-auth-data auth)
      (let ((ablk (drx:make-xdr-block :buffer abuf
				      :offset astart
				      :count aend)))
	(let ((gcred (decode-gss-cred ablk)))
	  ;; See RFC2203 section 5.3.3.3 for error status conditions
	  
	  ;; badcred error if version not correct
	  (unless (= (gss-cred-version gcred) +gss-version+)
	    (error 'auth-error :stat :badcred))
	  
	  (ecase (gss-cred-proc gcred)
	    (:init
	     ;; this is an initial call to the null proc to setup the context
	     ;; NOTE: this will signal an early exit using RPC-MANUAL-CALL
	     (handler-case (gss-server-init-context p gcred msg blk)
	       (error (e)
		 ;; (declare (ignore e))
		 ;; translate into rpc error		 
		 (format t "cred error ~A~%" e)
		 (error 'auth-error :stat +gss-cred-problem+))))
	    ((:data :destroy)
	     ;; if destroy then callproc must be 0 and there must be no args
	     (when (and (eq (gss-cred-proc gcred) :destroy)
			(or (not (= (call-body-proc
				     (drx:xunion-val (rpc-msg-body msg)))
				    0))
			    (not (= (drx:xdr-block-offset blk)
				    (drx:xdr-block-count blk)))))
	       (error 'auth-error :stat +gss-cred-problem+))
	     
	     (let ((cxt (gss-context-by-handle p (gss-cred-handle gcred))))
	       (unless cxt (error 'auth-error :stat +gss-cred-problem+))
	       (unless (<= (- (gss-cred-seqno gcred) (gss-context-seqno cxt))
			   (gss-context-seq-window cxt))
		 (error 'auth-error :stat +gss-context-problem+))

	       ;; update the context service level and current seqno
	       (setf (gss-context-service cxt) (gss-cred-service gcred)
		     (gss-context-seqno cxt) (gss-cred-seqno gcred))
	       
	       ;; the reply verifier is the checksum of the seqno
	       (let ((ablk (make-auth-block 4)))
		 (drx:encode-uint32 ablk (gss-cred-seqno gcred))
		 (let ((cksum (glass:get-mic (gss-context-context cxt)
					     (drx:xdr-block-buffer ablk))))

		   ;; if the proc is :destroy then delete the context
		   (when (eq (gss-cred-proc gcred) :destroy)
		     (delete-gss-context-by-handle p (gss-cred-handle gcred)))
		   
		   (values (make-opaque-auth :flavour :auth-gss
					     :data (list cksum 0 (length cksum)))
			 cxt)))))
	    (:continue
	     ;; TODO: support for multiple exchanges will require typing here
	     ;; currently unsupported
	     (error 'auth-error :stat +gss-cred-problem+))))))))


(defmethod server-modify-call ((p gss-server-provider) cxt blk start end)
  (when (eq (gss-context-service cxt) :privacy)
    ;; if the service level is :privacy it is also encrypted
    (let ((ibuf
	   (glass:unwrap (gss-context-context cxt)
			 (decode-gss-priv-data blk))))
      ;; write this into the block and update offsets
      (dotimes (i (length ibuf))
	(setf (aref (drx:xdr-block-buffer blk) (+ start i))
	      (aref ibuf i)))
      (setf (drx:xdr-block-count blk) (+ start (length ibuf))
	    (drx:xdr-block-offset blk) start)))

  (when (member (gss-context-service cxt) '(:integrity :privacy))
    ;; if the service level is :integrity the arg
    ;; is hidden inside an integ-data
    (let ((idata (decode-gss-integ-data blk)))
      ;; check the checksum
      (unless (glass:verify-mic (gss-context-context cxt)
				(gss-integ-data-integ idata)
				(gss-integ-data-checksum idata))
	;; section 5.3.3.4.1 says a failure to verify MIC is garbage args
	(error 'accept-error :stat :garbage-args))
      ;; check the seqnos
      (let* ((ablk (drx:make-xdr-block :buffer (gss-integ-data-integ idata)
				      :count (length (gss-integ-data-integ idata))))
	     (sqno (drx:decode-uint32 ablk)))
	(unless (= sqno (gss-context-seqno cxt))
	  (error 'auth-error :stat :tooweak))

	(let* ((adata (drx:decode-opaque ablk))
	       (len (length adata)))
	  ;; write the data back into the block
	  (do ((i 0 (1+ i)))
	      ((= i (length adata)))
	    (setf (aref (drx:xdr-block-buffer blk) (+ start i))
		  (aref adata i)))
	  (setf (drx:xdr-block-offset blk)
		start
		(drx:xdr-block-count blk)
		(+ start len)))))))

(defmethod server-modify-reply ((p gss-server-provider) cxt blk start end)
  (when (member (gss-context-service cxt) '(:integrity :privacy))
    ;; compute the checksum
    (let* ((adata (subseq (drx:xdr-block-buffer blk)
			  start end))
	   (ablk (make-auth-block (+ (length adata) 64))))
      ;; encode the seqno into the block
      (drx:encode-uint32 ablk (gss-context-seqno cxt))
      (drx:encode-opaque ablk adata)
      (let* ((iv (subseq (drx:xdr-block-buffer ablk)
			 0 (drx:xdr-block-offset ablk)))
	     ;; Section 5.3.3.4.1 says a failure to GSS_GetMIC when
	     ;; signing the call results should mean no response to the client. 
	     (chksum (handler-case (glass:get-mic (gss-context-context cxt)
						  iv)
		       (error (e)
			 (declare (ignore e))
			 (rpc-discard-call))))
	     (idata (make-gss-integ-data
		    :integ iv
		    :checksum chksum)))
	(ecase (gss-context-service cxt)
	  (:integrity
	   ;; just write this into the block
	   (setf (drx:xdr-block-offset blk) start)
	   (encode-gss-integ-data blk idata))
	  (:privacy
	   ;; encrypt and write
	   (drx:reset-xdr-block ablk)
	   (encode-gss-integ-data ablk idata)
	   
	   (setf (drx:xdr-block-offset blk) start)
	   (encode-gss-priv-data
	    blk
	    (glass:wrap (gss-context-context cxt)
			(subseq (drx:xdr-block-buffer ablk)
				0
				(drx:xdr-block-offset ablk))))))))))

