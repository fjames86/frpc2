
(defpackage #:frpc2.test.timing
  (:use #:cl #:frpc2))

(in-package #:frpc2.test.timing)

(defun mean (nums)
  (/ (reduce #'+ nums)
     (length nums)))

(defun standard-deviation (nums)
  (let* ((m (mean nums))
	 (v 0))
    (dolist (n nums)
      (incf v (* (- n m) (- n m))))
    (sqrt (/ v (length nums)))))

(defmacro with-timing ((nrepeats ntimes) &body body)
  (let ((gstart (gensym))
	(gnums (gensym)))
    `(let ((,gnums
	    (loop :for i :below ,ntimes
	       :collect
	       (let ((,gstart (get-internal-real-time)))
		 (dotimes (j ,nrepeats) ,@body)
		 (/ (- (get-internal-real-time) ,gstart)
		    (* ,nrepeats internal-time-units-per-second))))))
       (values (mean ,gnums)
	       (standard-deviation ,gnums)))))
  
;; -------------------------------

(defun time-new-client-udp (nrepeats ntimes)
  (with-rpc-client (c udp-client)
    (with-timing (nrepeats ntimes)
      (call-rpcbind-null c))))

(defun time-new-client-tcp (nrepeats ntimes)
  (with-rpc-client (c tcp-client :addr (fsocket:sockaddr-in #(127 0 0 1) 111))
    (with-timing (nrepeats ntimes)
      (call-rpcbind-null c))))

;; -------------------------------------

(defun time-old-client-udp (nrepeats ntimes)
  (frpc:with-rpc-connection (c "localhost" 111 :udp)
    (with-timing (nrepeats ntimes)
      (frpc.bind:call-null :connection c))))

(defun time-old-client-tcp (nrepeats ntimes)
  (frpc:with-rpc-connection (c "localhost" 111 :tcp)
    (with-timing (nrepeats ntimes)
      (frpc.bind:call-null :connection c))))

;; ----------------------------------

(defun timings (nrepeats ntimes)
  (multiple-value-bind (m s)
      (time-new-client-tcp nrepeats ntimes)
    (format t "New Client TCP : ~G +/- ~G~%" m s))
  
  (multiple-value-bind (m s)
      (time-new-client-udp nrepeats ntimes)
    (format t "New Client UDP ~G +/- ~G~%" m s))
  
  (multiple-value-bind (m s)
      (time-old-client-tcp nrepeats ntimes)
    (format t "Old Client TCP: ~G +/- ~G~%" m s))
  
  (multiple-value-bind (m s)
      (time-old-client-udp nrepeats ntimes)
    (format t "Old Client UDP ~G +/- ~G~%" m s)))


;; -----------------------------------


;; for running the old server 
(defvar *server* nil)

(defun start-old-server ()
  (setf *server* (frpc:make-rpc-server :udp-ports '(111)
				       :tcp-ports '(111)))
  (frpc:start-rpc-server *server*))

(defun stop-old-server ()
  (frpc:stop-rpc-server *server*))
