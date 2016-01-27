;;;; Copyright (c) Frank James 2016 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(in-package #:frpc2)

(defconstant +rpc-call+ 0)
(defconstant +rpc-reply+ 1)
(defxenum msg-type ()
  (:call +rpc-call+)
  (:reply +rpc-reply+))

(defconstant +msg-accepted+ 0)
(defconstant +msg-rejected+ 1)
(defxenum reply-stat ()
  (:msg-accepted +msg-accepted+)
  (:msg-rejected +msg-rejected+))

(defconstant +accept-success+ 0)
(defconstant +accept-prog-unavail+ 1)
(defconstant +accept-prog-mismatch+ 2)
(defconstant +accept-proc-unavail+ 3)
(defconstant +accept-garbage-args+ 4)
(defconstant +accept-system-error+ 5)
(defxenum accept-stat ()
  (:success +accept-success+)
  (:prog-unavail +accept-prog-unavail+)
  (:prog-mismatch +accept-prog-mismatch+)
  (:proc-unavail +accept-proc-unavail+)
  (:garbage-args +accept-garbage-args+)
  (:system-error +accept-system-error+))
            
(defconstant +reject-rpc-mismatch+ 0)
(defconstant +reject-auth-error+ 1)
(defxenum reject-stat ()
  (:rpc-mismatch +reject-rpc-mismatch+)
  (:auth-error +reject-auth-error+))

(defconstant +auth-badcred+ 1)
(defconstant +auth-rejected+ 2)
(defconstant +auth-badverf+ 3)
(defconstant +auth-rejectedverf+ 4)
(defconstant +auth-tooweak+ 5)
(defxenum auth-stat ((:exclusive nil))
  (:badcred +auth-badcred+)
  (:rejected +auth-rejected+)
  (:badverf +auth-badverf+)
  (:rejectedverf +auth-rejectedverf+)
  (:tooweak +auth-tooweak+))

(defxenum opaque-auth-flavour ((:exclusive nil))
  (:auth-null 0)
  (:auth-unix 1)
  (:auth-short 2)
  (:auth-des 3)
  (:auth-krb4 4)
  (:auth-rsa 5) ;; AUTH_RSA/Gluster, the Gluster protocols use this for their own flavour 
  (:auth-gss 6)
  
  ;; These are needed for NFS, see rfc5531 https://tools.ietf.org/html/rfc5531
  (:auth-spnego 390000)
  (:auth-krb5 390003)
  (:auth-krb5-integrity 390004)
  (:auth-krb5-privacy 390005))

(defxstruct opaque-auth ()
  (flavour opaque-auth-flavour :auth-null)
  (data :opaque* (list nil 0 0)))

(defxstruct call-body ()
  (rpcvers :uint32)
  (program :uint32)
  (version :uint32)
  (proc :uint32)
  (auth opaque-auth)
  (verf opaque-auth))

(defxstruct mismatch-data ()
  (low :uint32)
  (high :uint32))

(defxunion accepted-reply-body ((:enum accept-stat))
  (:success :void)
  (:prog-mismatch mismatch-data)
  (t :void))

(defxstruct accepted-reply ()
  (verf opaque-auth)
  (body accepted-reply-body))

(defxunion rejected-reply ((:enum reject-stat))
  (:rpc-mismatch mismatch-data)
  (:auth-error auth-stat))

(defxunion reply-body ((:enum reply-stat))
  (:msg-accepted accepted-reply)
  (:msg-rejected rejected-reply))

(defxunion msg-body ((:enum msg-type))
  (:call call-body)
  (:reply reply-body))

(defxstruct rpc-msg ()
  (xid :uint32)
  (body msg-body))

;; --------------------------

(defun make-rpc-call (program version proc &key auth verf xid)
  (make-rpc-msg :xid (or xid (random #xffffffff))
                :body (make-xunion :call
                                   (make-call-body :rpcvers 2
                                                   :program program
                                                   :version version
                                                   :proc proc
                                                   :auth (or auth (make-opaque-auth))
                                                   :verf (or verf (make-opaque-auth))))))

(defun make-rpc-reply (xid stat &key verf mismatch)
  (make-rpc-msg :xid xid
                :body (make-xunion :reply
                                   (make-xunion :msg-accepted
                                                (make-accepted-reply
                                                 :verf (or verf (make-opaque-auth))
                                                 :body (make-xunion stat mismatch))))))

(defun make-rpc-auth-reply (xid stat)
  (make-rpc-msg :xid xid
                :body (make-xunion :reply
                                   (make-xunion :msg-rejected
                                                (make-xunion :auth-error stat)))))



(defun rpc-reply-verf (msg)
  (let ((b (rpc-msg-body msg)))
    (unless (eq (xunion-tag b) :reply)
      ;; not a reply when a reply was expected. signal a garbage args error 
      (error 'accept-error :stat :garbage-args))
    (let ((m (xunion-val b)))
      (unless (eq (xunion-tag m) :msg-accepted)
        (let ((rr (xunion-val m)))
          ;; rr == rejected reply
          (ecase (xunion-tag rr)
            (:rpc-mismatch
             (let ((mismatch (xunion-val rr)))
               (error 'rpc-mismatch-error
                      :msg "LOW ~A HIGH ~A"
                      :arguments (list (mismatch-data-low mismatch) (mismatch-data-high mismatch)))))
            (:auth-error
             (let ((stat (xunion-val rr)))
               (error 'auth-error :stat stat))))))
      (let ((a (xunion-val m)))
        (unless (eq (xunion-tag (accepted-reply-body a)) :success)
          (error 'accept-error :stat (xunion-tag (accepted-reply-body a))))
        (accepted-reply-verf a)))))

(defun rpc-call-body (msg)
  (let ((body (rpc-msg-body msg)))
    (unless (eq (xunion-tag body) :call)
      ;; not a call when a call was expected, signal a garbage args error
      (error 'accept-error :stat :garbage-args))
    (xunion-val body)))
        
