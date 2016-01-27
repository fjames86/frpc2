;;;; Copyright (c) Frank James 2016 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.


(defpackage #:frpc2.test3
  (:use #:cl #:frpc2))

(in-package #:frpc2.test3)

(defun test-call-null-udp (addr)
  (let ((client (make-instance 'udp-client :addr addr)))
    (unwind-protect (call-rpcbind-null client)
      (transport-close client))))

(defun test-call-null-tcp (addr)
  (let ((client (make-instance 'tcp-client :addr addr)))
    (unwind-protect (call-rpcbind-null client)
      (transport-close client))))


(defgeneric myfn2 (x)
  (:method-combination or))

(defmethod myfn2 or ((x (eql :a)))
  nil)
(defmethod myfn2 or ((x (eql :b)))
  t)

