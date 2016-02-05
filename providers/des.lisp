;;;; Copyright (c) Frank James 2016 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.


(defpackage #:frpc2.des
  (:use #:cl #:frpc2)
  (:export #:des-client-provider
	   #:des-server-provider 
	   #:find-public-key 
	   #:add-public-key
	   #:remove-public-key 
	   #:list-public-keys
	   #:des-secret 
	   #:des-public))

(in-package #:frpc2.des)


;;; This file defines an AUTH_DES provider, also known as "secure RPC".
;;; The premise to use a Diffie-Hellman exchange and encrypted timestamps
;;; to prove recent knowledge of the client's secret key.
;;; NOTE: this authentication flavour was cracked by the early 90s and
;;; has long since been known to be insecure. The main reason for this
;;; is the short modulus. You could design your own flavour which is essentially
;;; the same but with a differnt modulus.
;;;
;;; It's defined here for the cases where it's required, to show what's possible,
;;; as an example of how to write one of these providers.
;;;
;;; TODO: This code is derived from an older version, frpc. 
;;; Some of the function naming is a bit inconsistent and in some places
;;; contradictory. Many functions are DH- or DES- when they should be vice versa.


;; -------------------------------------

(drx:defxenum authdes-namekind ()
  (:fullname 0)
  (:nickname 1))

(drx:defxfixed des-window () 4)

;; the client sends this to the server in the first request
(drx:defxstruct authdes-fullname ((:mode :plist))
  (name :string)
  (key :opaque) ;; encrypted conversation key
  (window des-window)) ;; encrypted window

(drx:defxunion authdes-cred ((:enum authdes-namekind))
  (:fullname authdes-fullname) ;; only used in the first request
  (:nickname :int32)) ;; all other requests use the nickname 

(drx:defxstruct authdes-timestamp ((:mode :plist))
  (seconds :uint32)
  (useconds :uint32))

;; the verifier sent by the client
(drx:defxstruct authdes-verf-client ()
  (adv-timestamp :opaque) ;; encrypted timestamp
  (adv-winverf des-window)) ;; encrypted (window - 1) only used in the first request

;; the verifier sent by the server 
(drx:defxstruct authdes-verf-server ()
  (adv-timeverf :opaque) ;; encrypted (timestamp - 1)
  (adv-nickname :int32)) ;; nickname to be used for the conversation

;; ----------------------------------------

;; these constants are specified in the rfc
(defconstant +dh-base+ 3)
(defconstant +dh-modulus+
  (parse-integer "d4a0ba0250b6fd2ec626e7efd637df76c716e22d0944b88b" 
		 :radix 16))

(defun dh-key (number)
  "Convert a number into a 192-bit DH key."
  (let ((key (nibbles:make-octet-vector 24)))
    (dotimes (i 24)
      (setf (aref key (- 24 i)) (logand number #xff)
	    number (ash number -8)))
    key))

(defun dh-conversation-key ()
  "Generate a random 56-bit (8-octet) DES key to be used as the conversation key"
  (let ((key (nibbles:make-octet-vector 8)))
    (dotimes (i 8)
      (let ((n (random 256)))
	(when (zerop (logcount n))
	  (setf n (1+ n)))
	(setf (aref key i) n)))
    key))

(defun dh-secret-key ()
  "Generate a random secret key"
  (do ((secret 0)
       (i 0 (1+ i)))
      ((= i 8) secret)
    (setf secret (+ (* secret 256) (random 256)))))

(defun discrete-expt-modulo (base exponent modulo)
  "Compute the value base**exponent % modulo. Uses the right-to-left binary method, as described on wikipedia."
  (declare (type integer base exponent modulo))
  (do ((result 1)
       (base (mod base modulo)))
      ((zerop exponent) result)
    (when (= (mod exponent 2) 1)
      (setf result (mod (* result base) modulo)))
    (setf exponent (ash exponent -1)
	  base (mod (* base base) modulo))))

(defun dh-public-key (secret)
  "Generate the public key from the secret key."
  (discrete-expt-modulo +dh-base+ secret +dh-modulus+))

(defun dh-common-key (secret public)
  "Generate the common key from the local private key and remote public key."
  (let ((common (discrete-expt-modulo public secret +dh-modulus+)))
    (let ((bytes (nibbles:make-octet-vector 8)))
      (setf (nibbles:ub64ref/be bytes 0) (logand common #xffffffffffffffff))
      (dotimes (i 8)
	(let ((parity (logcount (aref bytes i))))
	  (unless (zerop parity)
	    (setf (aref bytes i)
		  (logior (aref bytes i) 1)))))
    bytes)))
    
(defun make-dh-cipher (key &optional initial)			     
  "Make a cipher to use for encryption. If used to encrypt the initial client verifier,
INITIAL should be T. Otherwise INITIAL should be nil."
  (ironclad:make-cipher :des
			:mode (if initial :cbc :ecb)
			:key key
			:initialization-vector (nibbles:make-octet-vector 8)))

(defun dh-encrypt (cipher data)
  (let ((result (nibbles:make-octet-vector (length data))))
    (ironclad:encrypt cipher data result)
    result))

(defun dh-decrypt (cipher data)
  (let ((result (nibbles:make-octet-vector (length data))))
    (ironclad:decrypt cipher data result)
    result))

(defun dh-encrypt-conversation-key (common-key conv-key)
  (let ((c (make-dh-cipher common-key)))
    (dh-encrypt c conv-key)))

(defun dh-decrypt-conversation-key (common-key data)
  (let ((c (make-dh-cipher common-key)))
    (dh-decrypt c data)))

(defun des-timestamp (&optional seconds useconds)
  "Time since midnight March 1st 1970"
  (list 'seconds 
	(or seconds 
	    (- (get-universal-time)
	       (encode-universal-time 0 0 0 1 3 1970 0)))  ;; note: march 1st, not Jan 1st!
	'useconds 
	(or useconds 0)))

(defun encrypt-des-timestamp (key &optional timestamp)  
  (let ((blk (make-auth-block 8)))
    (encode-authdes-timestamp blk (or timestamp (des-timestamp)))
    (dh-encrypt (make-dh-cipher key) (drx:xdr-block-buffer blk))))

(defun decrypt-des-timestamp (key buffer)
  (let* ((v (dh-decrypt (make-dh-cipher key)
			(concatenate '(vector (unsigned-byte 8)) buffer)))
	 (blk (drx:make-xdr-block :buffer v :count (length v))))
    (decode-authdes-timestamp blk)))

(drx:defxstruct des-enc-block ((:mode :list))
  (timestamp authdes-timestamp)
  (window :uint32) ;; window
  (wverf :uint32)) ;; window-1

(defun des-client-verifier (conversation)
  "Generates a DES verifier for normal transactions."
  (let ((blk (make-auth-block 16)))
    (encode-authdes-verf-client blk 
				(make-authdes-verf-client :adv-timestamp (encrypt-des-timestamp conversation)
							  :adv-winverf (nibbles:make-octet-vector 4))) ;; FIXME: unused, just 0 octets????
    (make-opaque-auth :flavour :auth-des
		      :data (list (drx:xdr-block-buffer blk) 0 (drx:xdr-block-offset blk)))))
  
(defun des-server-verifier (conversation timestamp nickname)
  "Generate a DES verifier that the server responds with."
  (let ((blk (make-auth-block 16)))
    (encode-authdes-verf-server blk 
				(make-authdes-verf-server 
				 :adv-timeverf 
				 (encrypt-des-timestamp conversation
							(des-timestamp (1- (getf timestamp 'seconds))
								       (getf timestamp 'useconds)))
				 :adv-nickname 
				 nickname))
    (make-opaque-auth :flavour :auth-des
		      :data (list (drx:xdr-block-buffer blk) 0 (drx:xdr-block-offset blk)))))

(defun des-valid-server-verifier (conversation timestamp verf)
  "Check the timestamp is 1- the timestamp we sent"
  (let ((ts (decrypt-des-timestamp conversation 
				   (authdes-verf-server-adv-timeverf verf))))
    (= (1+ (getf ts 'seconds))
       (getf timestamp 'seconds))))

(defun des-secret ()
  "Generate a random DES secret key."
  (random +dh-modulus+))

(defun des-public (secret)
  "Generate a DES public key from the secret key."
  (declare (type integer secret))
  (dh-public-key secret))

(defun des-conversation ()
  "Make a random conversation key."
  (dh-conversation-key))

;; ------------------------------------

(defun des-initial-auth (conversation name client-secret server-public window timestamp)
  "Make a DES authenticator for initial requests."
  (let ((common (dh-common-key client-secret server-public)))
    ;; form a 2-block array and encrypt using the conversation key in CBC mode
    (let ((blk (make-auth-block 16)))
      (encode-des-enc-block blk (list timestamp window (1- window)))
      (let ((v (dh-encrypt (make-dh-cipher conversation t) (drx:xdr-block-buffer blk)))
	    (blk2 (make-auth-block)))
	(encode-authdes-cred blk2 
			     (drx:make-xunion :fullname 
					      (make-authdes-fullname
					       :name name 
					       :key (dh-encrypt-conversation-key common conversation)
					       ;; CHECKME
					       :window (subseq v 8 12))))
	(make-opaque-auth :flavour :auth-des 
			  :data (list (drx:xdr-block-buffer blk2) 0 (drx:xdr-block-offset blk2)))))))

(defun des-initial-verf (conversation window timestamp)
  "Make a DES verifier for initial requests."
  ;; form a 2-block array and encrypt using the conversation key in CBC mode
  (let ((blk (make-auth-block 16)))
    (encode-des-enc-block blk (list timestamp window (1- window)))
    (let ((v (dh-encrypt (make-dh-cipher conversation t)
			 (drx:xdr-block-buffer blk)))
	  (blk2 (make-auth-block 16)))
      ;; CHECKME 
      (encode-authdes-verf-client blk2 (make-authdes-verf-client :adv-timestamp (subseq v 0 8)
								 :adv-winverf (subseq v 12 16)))
      (make-opaque-auth :flavour :auth-des
			:data (list (drx:xdr-block-buffer blk2) 0 (drx:xdr-block-offset blk2))))))


(defun des-auth (nickname)
  "Make a DES authenticator for subsequent client calls."
  (let ((blk (make-auth-block 4)))
    (encode-authdes-cred blk (drx:make-xunion :nickname nickname))
    (make-opaque-auth :flavour :auth-des
		      :data (list (drx:xdr-block-buffer blk) 0 (drx:xdr-block-offset blk)))))

(defun des-verf (conversation)
  "Make a DES verifier for subsequent client calls."
  (let ((blk (make-auth-block 16)))
    (encode-authdes-verf-client blk 
				(make-authdes-verf-client :adv-timestamp (encrypt-des-timestamp conversation)
							  :adv-winverf (nibbles:make-octet-vector 4)))
    (make-opaque-auth :flavour :auth-des
		      :data (list (drx:xdr-block-buffer blk) 0 (drx:xdr-block-offset blk)))))


(defclass des-client-provider (client-provider)
  ((name :initarg :name :reader des-provider-name)
   (secret :initarg :secret :accessor des-provider-secret)
   (public :initarg :public :accessor des-provider-public)
   (key :initform (des-conversation) :accessor des-provider-key)
   (window :initarg :window :initform 300 :reader des-provider-window)
   (nickname :initform nil :accessor des-provider-nickname)
   (timestamp :initform nil :accessor des-provider-timestamp)))


(defmethod client-authenticate ((p des-client-provider) msg)
  (declare (ignore msg))
  
  ;; generate an auth and verf structure 
  (let ((timestamp (des-timestamp)))
    (cond 
      ((des-provider-nickname p)
       (setf (des-provider-timestamp p) timestamp)
       ;; we already have a nickname, use that 
       (values (des-auth (des-provider-nickname p))
	       (des-verf (des-provider-key p))))
      (t 
       ;; initial call to allocate a nickname 
       (setf (des-provider-timestamp p) timestamp)
       (values (des-initial-auth (des-provider-key p)
				 (des-provider-name p)
				 (des-provider-secret p)
				 (des-provider-public p)
				 (des-provider-window p)
				 timestamp)
	       (des-initial-verf (des-provider-key p)
				 (des-provider-window p)
				 timestamp))))))

(defmethod client-verify ((p des-client-provider) verf)
  ;; check the verifier is correct and store the nickname 
  (when (eq (opaque-auth-flavour verf) :auth-des)
    (destructuring-bind (a start end) (opaque-auth-data verf)
      (let* ((blk (drx:make-xdr-block :buffer a :offset start :count end))
	     (v (decode-authdes-verf-server blk)))
	(unless (des-valid-server-verifier (des-provider-key p)
					   (des-provider-timestamp p)
					   v)
	  (error 'rpc-error :msg "Invalid DES verifier"))
	(setf (des-provider-nickname p) (authdes-verf-server-adv-nickname v)))))	
  nil)

;; ---------------------- database ------------------------

;; we need a way of storing and looking up public keys.
;; The obvious options are either an RPC interface to a central repository or a shared-memory database.
;; We choose the database because it's easier.

(defun integer-keybuf (integer)
  "Convert a bignum to a keybuffer"
  (do ((nums nil)
       (n integer (ash n -8)))
      ((zerop n) (concatenate '(vector (unsigned-byte 8)) (nreverse nums)))
    (push (mod n 256) nums)))

(defun keybuf-integer (keybuf)
  "Convert a keybuffer back to a bignum."
  (do ((i (1- (length keybuf)) (1- i))
       (n 0))
      ((< i 0) n)
    (setf n (+ (ash n 8) (aref keybuf i)))))

(drx:defxencoder des-db-key (blk key)
  (drx:encode-opaque blk (integer-keybuf key)))
(drx:defxdecoder des-db-key (blk)
  (keybuf-integer (drx:decode-opaque blk)))

(drx:defxstruct des-db-entry ((:mode :list))
  (name :string)
  (key des-db-key))

(defvar *db* nil)
(defun open-db ()
  (unless *db*
    (setf *db*
	  (pounds.db:open-db (merge-pathnames "deskeys.dat"
					      (user-homedir-pathname))
			     (lambda (stream)
			       (let ((blk (make-auth-block 256)))
				 (read-sequence (drx:xdr-block-buffer blk) stream)
				 (decode-des-db-entry blk)))
			     (lambda (stream entry)
			       (let ((blk (make-auth-block 256)))
				 (encode-des-db-entry blk entry)
				 (write-sequence (drx:xdr-block-buffer blk) stream
						 :end (drx:xdr-block-offset blk))))
			     :block-size 256 
			     :count 256))))
(defun close-db ()
  (when *db*
    (pounds.db:close-db *db*)
    (setf *db* nil)))

(defun find-public-key (name)
  (open-db)
  (let ((entry (pounds.db:find-entry name *db*
				     :key #'first 
				     :test #'string-equal)))
    (when entry (second entry))))

(defun add-public-key (name key)
  (open-db)
  (setf (pounds.db:find-entry name *db*
			      :key #'first 
			      :test #'string-equal)
	(list name key)))

(defun remove-public-key (name)
  (open-db)
  (pounds.db:remove-entry name *db*
			  :key #'first 
			  :test #'string-equal))

(defun list-public-keys ()
  (open-db)
  (let (entries)
    (pounds.db:doentries (e *db*)
      (push e entries))
    entries))

;; -------------------- server ----------------------------

(defstruct des-context 
  fullname
  nickname
  timestamp
  key 
  window)

(defclass des-server-provider (server-provider)
  ((contexts :initform (make-list 32) :accessor des-provider-contexts)
   (secret :initarg :secret :accessor des-provider-secret)))

(defun add-des-context (p name timestamp conversation window)
  (let ((cxt (make-des-context :fullname name
			       :timestamp timestamp
			       :key conversation
			       :window window
			       :nickname (random #x80000000)))
	(oldest 0))
    (do ((cxts (des-provider-contexts p) (cdr cxts))
	 (age 0)
	 (i 0 (1+ i)))
	((null cxts))
      (when (null (car cxts))
	(setf (car cxts) cxt)
	(return-from add-des-context cxt))
      (when (or (zerop age) (< (getf (des-context-timestamp (car cxts)) 'seconds) age))
	(setf oldest i
	      age (getf (des-context-timestamp (car cxts)) 'seconds))))

    (setf (nth oldest (des-provider-contexts p)) cxt)
    cxt))

(defun find-des-context (p nickname)
  (find nickname (des-provider-contexts p) 
	:key #'des-context-nickname 
	:test #'=))

(defun des-valid-client-request (p auth verf)
  "This runs on the server and validates the initial client request. Returns a server verifier."
  (etypecase auth
    (list ;; authdes-fullname 
     (let* ((public (or (find-public-key (getf auth 'name))
			(error "No public key for ~A" (getf auth 'name))))
	    (common (dh-common-key (des-provider-secret p) public)))
       ;; start by getting the converation key from the authenticator
       (let ((conversation (concatenate '(vector (unsigned-byte 8))
					(dh-decrypt-conversation-key common 
								     (concatenate '(vector (unsigned-byte 8))
										  (getf auth 'key))))))
	 ;; now form the block and decrypt it
	 (let* ((v (dh-decrypt (make-dh-cipher conversation t)
			       (concatenate '(vector (unsigned-byte 8))
					    (authdes-verf-client-adv-timestamp verf)
					    (getf auth 'window)
					    (authdes-verf-client-adv-winverf verf))))
		(blk (drx:make-xdr-block :buffer v :count (length v))))
	   ;; unpack it 
	   (destructuring-bind (timestamp window winverf) (decode-des-enc-block blk)
	     ;; compare the timestamp and window, if it is valid then allocate a context
	     (let ((ts (getf (des-timestamp) 'seconds)))
	       (cond
		 ((and (< (abs (- (getf timestamp 'seconds) ts)) window)
		       (= winverf (1- window)))
		  (let ((context (add-des-context p
						  (getf auth 'name)
						  timestamp
						  conversation
						  window)))
		    (values (des-server-verifier conversation timestamp (des-context-nickname context))
			    context)))
		 (t 
		  (frpc2-log :trace "Invalid timestamp ~A:~A window ~A:~A" 
			     (getf timestamp 'seconds) ts window winverf)
		  (error 'auth-error :stat :tooweak)))))))))
    (integer 
     ;; this is a nickname, lookup the context 
     (let ((context (find-des-context p auth)))
       (if context 
	   (let ((timestamp (decrypt-des-timestamp (des-context-key context)
						   (authdes-verf-client-adv-timestamp verf))))

	     ;; verify the timestamp is later than the previous one 
	     (unless (and (>= (getf timestamp 'seconds) (getf (des-context-timestamp context) 'seconds))
			  (>= (getf timestamp 'useconds) (getf (des-context-timestamp context) 'useconds)))
	       (error "Timestamp ~S older than previous received timestamp ~S" 
		      timestamp (des-context-timestamp context)))
	     ;; verify the timestamp is within the window
	     (unless (< (abs (- (getf timestamp 'seconds) (getf (des-timestamp) 'seconds)))
			(des-context-window context))
	       (error "Timestamp ~S outside window" timestamp))

	     ;; all good -- update the context timestamp and return a verifier
	     (setf (des-context-timestamp context) timestamp)
	     (values (des-server-verifier (des-context-key context)
					  timestamp 
					  (des-context-nickname context))
		     context))
	   (error "No context for nickname ~A" auth))))))



(defmethod server-authenticate ((p des-server-provider) auth verf msg blk)
  (declare (ignore msg blk))
  (when (and (eq (opaque-auth-flavour auth) :auth-des)
	     (eq (opaque-auth-flavour verf) :auth-des))
    (destructuring-bind (abuf astart aend) (opaque-auth-data auth)
      (destructuring-bind (vbuf vstart vend) (opaque-auth-data verf)
	(let ((ablk (drx:make-xdr-block :buffer abuf :offset astart :count aend))
	      (vblk (drx:make-xdr-block :buffer vbuf :offset vstart :count vend)))
	  (let ((auth (decode-authdes-cred ablk))
		(verf (decode-authdes-verf-client vblk)))
	    (des-valid-client-request p (drx:xunion-val auth) verf)))))))

;; ----------------------------------------

