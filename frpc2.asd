;;;; Copyright (c) Frank James 2016 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(asdf:defsystem :frpc2
  :name "frpc2"
  :author "Frank James <frank.a.james@gmail.com>"
  :description "ONC-RPC implementation."
  :license "MIT"
  :serial t
  :components
  ((:file "package")
   (:file "log")
   (:file "errors")
   (:file "rpc")
   (:file "auth")
   (:file "client")
   (:file "bind")
   (:file "server")
   (:file "simple"))
  :depends-on (:drx :fsocket :bordeaux-threads :pounds :dragons))

(asdf:defsystem :frpc2.rpcbind
  :name "rpcbind"
  :author "Frank James <frank.a.james@gmail.com>"
  :description "rpcbind server"
  :license "MIT"
  :serial t
  :components
  ((:module :programs
	    :pathname "programs"
	    :components
	    ((:file "rpcbind"))))
  :depends-on (:frpc2 :pounds))

(asdf:defsystem :frpc2.des 
  :name "frpc2.des"
  :author "Frank James <frank.a.james@gmail.com>"
  :description "AUTH_DES authentication provider"
  :license "MIT"
  :serial t
  :components
  ((:module :providers
	    :pathname "providers"
	    :components
	    ((:file "des"))))
  :depends-on (:frpc2 :pounds :ironclad))

(asdf:defsystem :frpc2.gss
  :name "frpc2.gss"
  :author "Frank James <frank.a.james@gmail.com>"
  :description "AUTH_GSS authentication provider"
  :license "MIT"
  :serial t
  :components
  ((:module :providers
	    :pathname "providers"
	    :components
	    ((:file "gss"))))
  :depends-on (:frpc2 :pounds :ironclad :cerberus))

(asdf:defsystem :frpc2.test
  :name "frpc2.test"
  :author "Frank James <frank.a.james@gmail.com>"
  :description "tests and examples" 
  :license "MIT"
  :serial t
  :components
  ((:module :test
	    :pathname "test"
	    :components
	    ((:file "test1")
	     (:file "test2")
	     (:file "test3")
	     (:file "test4")
	     (:file "test-des")
	     (:file "test-gss"))))
  :depends-on (:frpc2))
