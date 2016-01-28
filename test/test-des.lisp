;;;; Copyright (c) Frank James 2016 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.


(defpackage #:frpc2.test-des
  (:use #:cl #:frpc2))

(in-package #:frpc2.test-des)

(defun handle-testprog-null (server arg)
  (declare (ignore server arg))
  nil)

(define-rpc-interface testprog (123321 1)
  (null :void :void))


(defvar *server* nil)

(defun start ()
  (unless *server*
    (setf *server*
	  (simple-rpc-server-construct
	   (list (testprog))
	   :udp-ports '(0)
	   :providers (list (make-instance 'frpc2.des:des-server-provider
					   :public (frpc2.des:des-public 123321)
					   :secret 123321)))))
  (simple-rpc-server-start *server*))

(defun stop ()
  (when *server*
    (simple-rpc-server-stop *server*)))

(defparameter *c* (make-instance 'udp-client
			   :provider (make-instance 'frpc2.des:des-client-provider
						    :name "frank"
						    :secret 111111
						    :public (frpc2.des:find-public-key "myserver"))
			   :addr (fsocket:make-sockaddr-in :addr #(127 0 0 1)
							   :port 111)))
