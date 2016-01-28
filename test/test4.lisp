;;;; Copyright (c) Frank James 2016 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(defpackage #:frpc2.test4
  (:use #:cl #:frpc2))

(in-package #:frpc2.test4)

(defun handle-myprogram-null (server arg)
  (declare (ignore server arg))
  nil)

(defun handle-myprogram-add1 (server x)
  (declare (ignore server))
  (1+ x))

(defun handle-myprogram-sub1 (server x)
  (declare (ignore server))
  (1- x))

(defun handle-myprogram-sq (server x)
  (declare (ignore server))
  (* x x))

(define-rpc-interface myprogram (123456 1)
  (null :void :void)
  (add1 :int32 :int32)
  (sub1 :int32 :int32)
  (sq :int32 :int32))

(defun run (port &key (timeout 15))
  (let ((fd (fsocket:open-socket))
        (pc (fsocket:open-poll))
        (programs (list (myprogram)))
        (providers (list (make-instance 'auth-null-provider))))
    (fsocket:socket-bind fd (fsocket:make-sockaddr-in :port port))
    (fsocket:poll-register pc (make-instance 'fsocket:pollfd
                                             :fd fd
                                             :events (fsocket:poll-events :pollin)))

    ;; register with the portmapper?
    ;; (let ((client (make-instance 'udp-client :addr (fsocket:make-sockaddr-in))))
    ;;   (call-rpcbind-set client (make-mapping :program 123456 :version 2 :port port :protocol :udp))
    ;;   (transport-close client))
    
    (do ((now (get-universal-time) (get-universal-time))
         (blk (drx:make-xdr-block))
         (end (+ (get-universal-time) timeout)))
        ((>= now end))
      (fsocket:doevents (pollfd event) (fsocket:poll pc :timeout 1000)
        (handler-case 
            (ecase event
              (:pollin
               (multiple-value-bind (count raddr)
                   (fsocket:socket-recvfrom (fsocket:pollfd-fd pollfd)
                                            (drx:xdr-block-buffer blk))
                 (format t "Received ~A bytes from ~A~%" count raddr)
                 (setf (drx:xdr-block-count blk) count
                       (drx:xdr-block-offset blk) 0)
                 (process-rpc-call blk 
                                   programs
                                   providers)
                 (fsocket:socket-sendto (fsocket:pollfd-fd pollfd)
                                        (drx:xdr-block-buffer blk)
                                        raddr
                                        :start 0 :end (drx:xdr-block-offset blk)))))
          (error (e)
            (format t "ERROR: ~A~%" e)))))

    (fsocket:close-socket fd)
    (fsocket:close-poll pc)))

                                    
  
