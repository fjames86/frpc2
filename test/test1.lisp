
;;;; This code is licensed under the MIT license.


(defpackage #:frpc2.test1
  (:use #:cl #:drx #:frpc2))

(in-package #:frpc2.test1)

(defparameter *programs* nil)


(defun handle-null (arg)
  (declare (ignore arg))
  (format t "Handling NULL~%")
  nil)

(defun handle-proc1 (arg)
  (format t "ARG: ~A~%" arg)
  (if (= arg 1000)
      (error 'frpc2::auth-error :stat :tooweak)
      (1+ arg)))

(defun make-myprog ()
  (list 100000 2
	(list (list #'handle-null #'decode-void #'encode-void)
	      (list #'handle-proc1 #'decode-uint32 #'encode-uint32))))

(push (make-myprog) *programs*)

(defparameter *blk* (make-xdr-block))

(defun test-call-null ()
  (reset-xdr-block *blk*)
  (encode-rpc-call *blk* #'encode-void nil
                   100000 2 0
                   :provider (make-instance 'auth-null-provider))
  ;; TODO: transport here
  (setf (xdr-block-offset *blk*) 0)
  (process-rpc-call *blk*
                    *programs*
                    (make-instance 'auth-null-provider)))

(defun test-call-proc1 (n)
  (reset-xdr-block *blk*)
  (let ((xid (encode-rpc-call *blk* #'encode-uint32 n
                              100000 2 1
                              :provider (make-instance 'auth-null-provider))))
    ;; TODO: transport here
    (setf (xdr-block-offset *blk*) 0)
    (process-rpc-call *blk*
                      *programs*
                      (make-instance 'auth-null-provider))
    (setf (xdr-block-offset *blk*) 0)
    (frpc2::decode-rpc-reply *blk* #'decode-uint32
                             xid (make-instance 'auth-null-provider))))


