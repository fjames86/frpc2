;;;; Copyright (c) Frank James 2016 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(defpackage #:frpc2.test-gss
  (:use #:cl #:frpc2 #:frpc2.gss))

(in-package #:frpc2.test-gss)

(defun handle-testprog-null (server arg)
  (declare (ignore server arg))
  nil)

(defun handle-testprog-proc1 (server arg)
  (declare (ignore server))
  (format t "ARG: ~A~%" arg)
  arg)

(define-rpc-interface testprog (123321 1)
  (null :void :void)
  (proc1 :opaque :opaque))

(defvar *server* nil)

(defun start ()
  (unless *server*
    (setf *server*
	  (simple-rpc-server-construct
	   (list (testprog))
	   :udp-ports '(0)
	   :providers
	   (list (make-instance 'gss-server-provider
				:creds
				(gss:acquire-credentials :kerberos nil)))))
    (simple-rpc-server-start *server*)))

(defun stop ()
  (when *server*
    (simple-rpc-server-stop *server*)
    (simple-rpc-server-destruct *server*)
    (setf *server* nil)))

(defun test-client (&optional service)
  (let ((addr (get-rpc-address 123321 1)))
    (format t "addr ~A~%" addr)
    (with-rpc-client (c udp-client
			:provider
			(make-gss-client-provider
			 addr
			 123321
			 1
			 (gss:acquire-credentials :kerberos "Administrator@ANGELO.EXSEQUI.COM")
			 (or service :privacy))
			:addr addr)
      (format t "blk count: ~A~%" (drx:xdr-block-count (frpc2::rpc-client-block c)))

      (format t "Call NULL~%")
      (call-testprog-null c)

      (let ((args (concatenate '(vector (unsigned-byte 8)) #(1 2 3 4))))
	(format t "Call PROC1 ~A~%" args)
	(format t "-> ~A~%" (call-testprog-proc1 c args))))))
	
