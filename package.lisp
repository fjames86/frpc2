;;;; Copyright (c) Frank James 2016 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(defpackage #:frpc2
  (:use #:cl #:drx)
  (:export #:process-rpc-call

           ;; authentication providers
           #:make-auth-block           
           #:client-provider 
           #:client-authenticate
           #:client-verify
	   #:client-modify-call
	   #:client-modify-reply
           #:server-provider
           #:server-authenticate
	   #:server-modify-call
	   #:server-modify-reply

	   ;; some rpc structure accessors that may be required 
	   #:rpc-msg	   
	   #:encode-rpc-msg
	   #:decode-rpc-msg 
	   #:rpc-msg-xid
	   #:rpc-msg-body
	   #:call-body-auth
	   #:call-body-verf
	   #:call-body-proc

	   ;; call and reply encoders
           #:encode-rpc-call
	   #:make-rpc-reply 
           #:decode-rpc-reply
	   #:rpc-reply-verf
	   
           ;; errors and conditions 
           #:rpc-error
           #:accept-error
           #:auth-error
           #:rpc-mismatch-error
           #:rpc-timeout-error
           #:rpc-discard-call
           #:rpc-manual-reply

	   ;; auth structures
           #:opaque-auth
           #:make-opaque-auth 
           #:opaque-auth-flavour
           #:opaque-auth-data

	   ;; server pollfds
	   #:udp-pollfd
	   #:udp-pollfd-addr 
	   #:udp-pollfd-blk 
	   #:tcp-pollfd
	   #:tcp-pollfd-addr 

           ;; clients
           #:rpc-client
	   #:rpc-client-close 
	   #:rpc-client-provider
	   
           #:udp-client
	   #:udp-client-addr
	   #:bind-udp-client
	   #:broadcast-client	   
           #:tcp-client

	   ;; useful functions 
           #:call-rpc
	   #:send-rpc
	   #:recv-rpc 
	   #:with-rpc-client
	   #:generate-program-number
	   
	   ;; define clients and server programs
	   #:defrpc 
	   #:define-rpc-client
	   #:define-rpc-server 
	   #:define-rpc-interface
	   #:declare-rpc-interface
	   
           ;; rpcbind 
           #:mapping
           #:make-mapping
           #:mapping-program
           #:mapping-version
           #:mapping-protocol
           #:mapping-port
           #:mapping-list
           #:mapping-list-opt           
           #:callit-arg
	   #:make-callit-arg 
           #:callit-arg-program
           #:callit-arg-version
           #:callit-arg-proc
           #:callit-arg-args
           #:callit-res
	   #:callit-res-port
	   #:callit-res-res
	   #:encode-callit-res
	   
           #:call-rpcbind-null
           #:call-rpcbind-set
           #:call-rpcbind-unset
           #:call-rpcbind-getport
           #:call-rpcbind-dump
           #:call-rpcbind-callit
	   #:get-rpc-address
	   #:get-rpc-programs
	   #:get-rpc-hosts
	   
           ;; general server. only processes calls, does no networking
           #:rpc-server
	   #:rpc-server-programs
	   #:rpc-server-provider-context 
	   #:rpc-server-auth-flavour
	   
           ;; simple server. Should be sufficient for most usages
	   #:simple-rpc-server 
           #:simple-rpc-server-await-reply
           #:simple-rpc-server-process
           #:simple-rpc-server-construct
           #:simple-rpc-server-destruct
           #:simple-rpc-server-start
           #:simple-rpc-server-stop
           #:simple-rpc-server-run
	   #:simple-rpc-server-rpfd 
	   #:simple-rpc-server-pc 
	   #:simple-rpc-server-msg 
	   #:simple-rpc-server-exiting 
	   #:simple-rpc-server-thread 
	   #:simple-rpc-server-purge-calls
	   #:simple-rpc-server-timeout
	   
	   ;; debug logging
	   #:frpc2-log
	   #:*frpc2-log*
	   #:open-log
	   #:close-log

           ;; AUTH_UNIX / AUTH_SHORT 
           #:unix
           #:unix-stamp
           #:unix-name
           #:unix-uid
           #:unix-gid
           #:unix-gids
           #:unix-client-provider
	   #:make-unix-provider 
           #:unix-server-provider 
                      
           ))

           

