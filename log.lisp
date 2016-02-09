;;;; Copyright (c) Frank James 2016 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(in-package #:frpc2)

(defvar *frpc2-log* nil)
(defvar *frpc2-log-levels* nil)

(defun open-log (&optional pathname)
  "Open the log. If PATHNAME is provided will be opened, otherwise uses the default."
  (unless *frpc2-log*
    (setf *frpc2-log*
          (pounds.log:open-log
	   :path (or pathname
		     (merge-pathnames "frpc2.log" (user-homedir-pathname)))
	   :tag "RPC2"))))

(defun close-log ()
  "Close the log."
  (when *frpc2-log*
    (pounds.log:close-log *frpc2-log*)
    (setf *frpc2-log* nil)))
  
(defun frpc2-log (lvl format-string &rest args)
  "Write into the debug log."
  (when (and *frpc2-log*
	     (or (null *frpc2-log-levels*)
		 (member lvl *frpc2-log-levels*)))
    (pounds.log:write-message *frpc2-log*
			      lvl
			      (apply #'format nil format-string args))))
  
