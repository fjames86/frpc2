;;;; Copyright (c) Frank James 2016 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(in-package #:frpc2)

;; This defines a client interface for portmapper (rpcbind version 2).

(defxenum mapping-protocol ()
  (:udp 17)
  (:tcp 6))

(defxstruct mapping ()
  (program :uint32)
  (version :uint32)
  (protocol mapping-protocol)
  (port :uint32))

(defxlist mapping-list () mapping)
(defxoptional mapping-list-opt () mapping-list)

(defxstruct callit-arg ()
  (program :uint32)
  (version :uint32)
  (proc :uint32)
  (args :opaque*))

(defxstruct callit-res ((:mode :list))
  (port :uint32)
  (res :opaque*))

;; (defun decode-callit-res-unwrapped (blk res-decoder)
;;   (let ((cres (decode-callit-res blk)))
;;     (destructuring-bind (port (buff start end)) cres
;;       (let ((rblk (make-xdr-block :buffer buffer :offset start :count end)))
;; 	(list port (funcall res-decoder rblk))))))

(defconstant +rpcbind-program+ 100000)
(defconstant +rpcbind-version+ 2)

(define-rpc-client rpcbind (+rpcbind-program+ +rpcbind-version+)
  (null :void :void)
  (set mapping :boolean)
  (unset mapping :boolean)
  (getport mapping :uint32)
  (dump :void mapping-list-opt)
  (callit% callit-arg callit-res))

;; define a somewhat nicer wrapping function for CALLIT 
(defun call-rpcbind-callit (client arg-encoder arg res-decoder program version proc)
  "Execute an RPC on the remote machine, proxyinb the call via the 
rpcbind service. 
CLIENT ::= rpc client to send the call with.
ARG-ENCODER ::= DrX XDR encoder function.
ARG ::= value to pass to ARG-ENCODER.
RES-DECODER ::= DrX XDR decoder function.
PROGRAM, VERSION, PROC ::= the procedure to invoke.

This function makes it possible to call a procedure without knowing the port
number to contact the program on (or even if the program exists). Its primary
use is to broadcast calls on the local network, facilitating 
e.g. service discovery.

The rpcbind service is silent if an error occurs.

The RPC is invoked on the remote host using the UDP protocol.

No authentication is possible."
  (let ((blk (xdr-block (* 8 1024))))
    ;; encode the argument data 
    (funcall arg-encoder blk arg)
    (let ((carg (make-callit-arg :program program
				 :version version
				 :proc proc
				 :args (list (xdr-block-buffer blk)
					     0
					     (xdr-block-offset blk)))))
      (let ((results (call-rpcbind-callit% client carg)))
	(flet ((decode-result (res)
		 (destructuring-bind (port (buff start end)) res
		   (let ((blk (make-xdr-block :buffer buff
					      :offset start
					      :count end)))
		     (list port (funcall res-decoder blk))))))
	  (if (typep client 'broadcast-client)
	      ;; broadcast clients return a list of (reply-addres result)* 
	      (mapcar (lambda (r)
			(destructuring-bind (raddr res) r
			  (list raddr (decode-result res))))
		      results)
	      ;; everything else just returns result 
	      (decode-result results)))))))

(defconstant +rpcbind-port+ 111)

(defun resolve-addr (host)
  (or (first (dns:get-host-by-name host))
      (error "Couldn't resolve host <~A>" host)))

(defun get-rpc-address (program version &optional host (protocol :udp))
  "Get the address to contact a specified program by contacting the rpcbind service.
PROGRAM, VERSION ::= integers specifying the program and version.
ADDR ::= if supplied should be a vector of 4 octets specifying the internet address of the host.
PROTOCOL ::= the desired protocol to contact, either :UDP or :TCP.

Returns an FSOCKET:SOCKADDR-IN address."
  (declare (type integer program version)
	   (type (member :udp :tcp) protocol))
  (let ((sin (fsocket:sockaddr-in (resolve-addr (or host #(127 0 0 1))) +rpcbind-port+)))
    (with-rpc-client (c udp-client :addr sin)
      (let ((port (call-rpcbind-getport c
					(make-mapping :program program
						      :version version
						      :protocol protocol
						      :port 0))))
	(if (zerop port)
	    (error 'accept-error :stat :prog-unavail)
	    (fsocket:sockaddr-in (fsocket:sockaddr-in-addr sin)
				 port))))))
  
(defun bind-udp-client (client program version &optional host)
  "Bind a UDP client to the address for the specified program. Contacts 
the hosts rpcbind service to discover the port number.

CLIENT ::= an instance of UDP-CLIENT.
PROGRAM, VERSION ::= integers specifying the program and version numbers.
HOST ::= a host specifier. Either a SOCKADDR-IN, a 4-octet vector, 
a dotted quad string or a string representing the hostname. In the later 
case a DNS resolver is used to resolve the internet address.
"
  (declare (type udp-client client)
	   (type integer program version))
  (let ((addr (get-rpc-address program version host)))
    (setf (udp-client-addr client) addr)
    addr))
      
(defun get-rpc-programs (&optional host)
  "Contact the RPCBIND service to get a list of program mappings. 
HOST ::= Host specifier, either dotted quad string, sockaddr-in or inaddr. Should be 
acceptable input for DRAGONS:GET-HOST-BY-NAME. 

Returns a list of MAPPING structures."
  (let ((sin (fsocket:sockaddr-in (resolve-addr host) +rpcbind-port+)))
    (with-rpc-client (c udp-client :addr sin)
      (call-rpcbind-dump c))))

(defun get-rpc-hosts (program version &optional (protocol :udp))
  "Find a list of hosts for the specified program by broadcasting 
to the rpcbind service. 
PROGRAM, VERSION ::= integers specifying the program.
PROTOCOL ::= The protocol you wish to contact the service on, 
either :UDP or :TCP.

Returns a list of SOCKADDR-IN structs for each host which is 
advertised as available on the local network. 
Note that rpcbind is contacted by broadcasting on the 
local network address 255.255.255.255."
  (with-rpc-client (c broadcast-client
		      :addr (fsocket:sockaddr-in #(255 255 255 255)
						 +rpcbind-port+))
    (let ((results (call-rpcbind-getport c
					 (make-mapping :program program
						       :version version
						       :protocol protocol
						       :port 0))))
      (mapcan (lambda (r)
		(destructuring-bind (raddr port) r
		  (unless (zerop port)
		    (setf (fsocket:sockaddr-in-port raddr) port)
		    (list raddr))))
	      results))))


;; ------------- RPCBIND versions 3 and 4 -------------------

;; (defxstruct binding ()
;;   (program :uint32)
;;   (version :uint32)
;;   (netid :string)
;;   (addr :string)
;;   (owner :string))

;; (defxlist binding-list () binding)
;; (defxoptional binding-list-opt () binding-list)

;; (defxstruct remote-call-arg ()
;;   (program :uint32)
;;   (version :uint32)
;;   (proc :uint32)
;;   (args (:varray* :octet)))

;; (defxstruct remote-call-res ()
;;   (addr :string)
;;   (result :opaque*))

;; (defxstruct bind-entry ()
;;   (maddr :string)
;;   (netid :string)
;;   (semantics :uint32)
;;   (family :string) ;; protocol family 
;;   (proto :string)) 

;; (defxlist bind-entry-list () bind-entry)
;; (defxoptional bind-entry-list-opt () bind-entry-list)

;; (defxstruct bind-addr ()
;;   (program :uint32)
;;   (version :uint32)
;;   (success :int32)
;;   (failure :int32)
;;   (netid :string))

;; (defxlist bind-addr-list () bind-addr)
;; (defxoptional bind-addr-list-opt () bind-addr-list)

;; (defxstruct remote-call ()
;;   (program :uint32)
;;   (version :uint32)
;;   (proc :uint32)
;;   (success :int32)
;;   (failure :int32)
;;   (indirect :int32)
;;   (netid :string))

;; (defxlist remote-call-list () remote-call)
;; (defxoptional remote-call-list-opt () remote-call-list)

;; (defconstant +bind-highproc+ 13)
;; (defxarray bind-proc () :uint32 +bind-highproc+)

;; (defxoptional addrinfo-opt () addr-list)

;; (defxstruct bind-stat ()
;;   (info bind-proc)
;;   (setinfo :int32)
;;   (unsetinfo :int32)
;;   (addrinfo addrinfo-opt)
;;   (rmtinfo remote-call-list-opt))

;; (defconstant +bind-vers-stat+ 3)
;; (defxarray stat-by-vers () bind-stat +bind-vers-stat+)

;; (defxstruct netbuf ()
;;   (maxlen :uint32)
;;   (data :opaque*))

;; (define-rpc-interface rpcbind3 (+rpcbind-program+ 3)
;;   (null :void :void)
;;   (set binding :boolean)
;;   (unset binding :boolean)
;;   (getaddr binding :string)
;;   (dump :void binding-list-opt)
;;   (broadcast remote-call-args remote-call-res)
;;   (gettime :void :uint32)
;;   (uaddr2taddr :string netbuf)
;;   (taddr2uaddr netebuf :string))

;; (define-rpc-interface rpcbind4 (+rpcbind-program+ 4)
;;   (null :void :void)
;;   (set binding :boolean)
;;   (unset binding :boolean)
;;   (getaddr binding :string)
;;   (dump :void binding-list-opt)
;;   (broadcast remote-call-args remote-call-res)
;;   (gettime :void :uint32)
;;   (uaddr2taddr :string netbuf)
;;   (taddr2uaddr netebuf :string)
;;   (versionaddr binding :string)
;;   (indirect remote-call-args remote-call-res)
;;   (addrlist binding entry-list-opt)
;;   (getstat :void stat-by-vers))




