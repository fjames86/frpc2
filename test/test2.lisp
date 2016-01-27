;;;; Copyright (c) Frank James 2016 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.


(defpackage #:frpc2.test2
  (:use #:cl #:drx #:frpc2))

(in-package #:frpc2.test2)

(defparameter *client* (make-instance 'udp-client))
                                      
(defun test-call-null (addr)
  (setf (udp-transport-addr *client*) addr)
  (let ((res (rpc-call *client* #'encode-void nil #'decode-void
                       100000 2 0)))
    (format t "Received reply from ~A~%" (udp-transport-raddr *client*))
    res))
  


