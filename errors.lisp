;;;; Copyright (c) Frank James 2016 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(in-package #:frpc2)

(define-condition rpc-error (error)
  ((msg :initarg :msg :reader rpc-error-msg))
  (:report (lambda (c stream)
             (format stream "RPC-ERROR: ~A" (rpc-error-msg c)))))

(defun rpc-error (format-string &rest args)
  (error 'rpc-error
         :msg (apply #'format nil format-string args)))

(define-condition accept-error (rpc-error)
  ((stat :initarg :stat :reader accept-error-stat))
  (:report (lambda (c stream)
             (format stream "ACCEPT-ERROR ~A" (accept-error-stat c)))))

(define-condition auth-error (rpc-error)
  ((stat :initarg :stat :reader auth-error-stat))
  (:report (lambda (c stream)
             (format stream "AUTH-ERROR ~A" (auth-error-stat c)))))

(define-condition rpc-mismatch-error (rpc-error)
  ())

(define-condition rpc-timeout-error (rpc-error)
  ()
  (:report (lambda (c stream)
             (declare (ignore c))
             (format stream "RPC-TIMEOUT-ERROR: timed out waiting for a response"))))
