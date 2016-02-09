

(defpackage #:frpc2.test.async
  (:use #:cl #:frpc2))

(in-package #:frpc2.test.async)

;;; This shows how to use the asynchronous client calls, SEND-RPC and RECV-RPC,
;;; rather than the canonical blocking CALL-RPC, which is essentially a send
;;; followed immediately by a recv.

(defun async-call-null (c)
  (send-rpc c
	    #'drx:encode-void nil
	    #'drx:decode-void
	    100000 2 0))

(defun test-async ()
  (with-rpc-client (c udp-client)
    (let ((xids nil))
      ;; send 10 calls 
      (dotimes (i 10)
	(push (cons (async-call-null c) nil)
	      xids))
      ;; await replies 
      (dotimes (i 10)
	(multiple-value-bind (result xid) (recv-rpc c)
	  (let ((pair (assoc xid xids)))
	    (when pair (setf (cdr pair) (list result))))))
      xids)))

(defun test-async-tcp ()
  (with-rpc-client (c tcp-client :addr (fsocket:sockaddr-in #(127 0 0 1) 111))
    (let ((xids nil))
      ;; send 10 calls 
      (dotimes (i 10)
	(push (cons (async-call-null c) nil)
	      xids))
      ;; await replies
      (dotimes (i 10)
	(multiple-value-bind (result xid) (recv-rpc c)
	  (let ((pair (assoc xid xids)))
	    (when pair (setf (cdr pair) (list result))))))
      xids)))
    
(defun test-async-tcp2 ()
  (with-rpc-client (c tcp-client :addr (fsocket:sockaddr-in #(127 0 0 1) 111))
    (send-rpc c #'drx:encode-void nil #'drx:decode-void
	      100000 2 0)
    (multiple-value-bind (r x) (recv-rpc c)
      (format t "R ~S X ~S~%" r x))
    (send-rpc c #'drx:encode-void nil #'drx:decode-void
	      100000 2 0)
    (multiple-value-bind (r x) (recv-rpc c)
      (format t "R ~S X ~S~%" r x))))

(defun test-async-tcp3 ()
  (with-rpc-client (c tcp-client :addr (fsocket:sockaddr-in #(127 0 0 1) 111))
    (format t "XID1 ~A~%"
	    (send-rpc c #'drx:encode-void nil #'drx:decode-void
		      100000 2 0))
    (format t "XID2 ~A~%"
	    (send-rpc c #'drx:encode-void nil #'drx:decode-void
		      100000 2 0))
    (multiple-value-bind (r x) (recv-rpc c)
      (format t "R ~S X ~S~%" r x))
    (multiple-value-bind (r x) (recv-rpc c)
      (format t "R ~S X ~S~%" r x))))

    
    
