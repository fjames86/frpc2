;;;; Copyright (c) Frank James 2016 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(in-package #:frpc2)

(defun find-rpc-handler (programs msg)
  (let ((pg (call-body-program (xunion-val (rpc-msg-body msg))))
        (vs (call-body-version (xunion-val (rpc-msg-body msg))))
        (pc (call-body-proc (xunion-val (rpc-msg-body msg)))))
    (dolist (program programs)
      (destructuring-bind (prg vrs handlers) program
        (when (and (= prg pg) (= vrs vs))
          (let ((cnt (length handlers)))
            (if (< pc cnt)
                (return-from find-rpc-handler (nth pc handlers))
                (error 'accept-error :stat :proc-unavail))))))
    (error 'accept-error :stat :prog-unavail)))
   
(defclass rpc-server ()
  ((programs :initform nil :initarg :programs :accessor rpc-server-programs)
   (providers :initform nil :initarg :providers :accessor rpc-server-providers)
   (flavour :initform nil :accessor rpc-server-auth-flavour
	    :documentation "The authentication flavour of the call currently being processed. Handlers can use this to decide whether the level of authentication is sufficient.")
   (provider-context :initform nil
		     :accessor rpc-server-provider-context
		     :documentation "The authentication context granted by the authentication provider for the currently processing call. Handlers can use this to query the authentication provider about the client. Since this is specific to the authentication flavour granted, you must consult your authentication provider's documentation for relevant details.")))
   
(defun rpc-manual-reply (blk msg res-encoder res)
  "Only valid in the context of: a provider's SERVER-AUTHENTICATE method, 
SERVER-MODIFY-CALL, SERVER-MODIFY-REPLY or a procedure handler. 

The server will reply immediately to the user with this message. This is useful for providers that
need to intercept calls and handle them itself instead of control passing to the normal procedure handler."
  (frpc2-log :trace "Manual reply")
  (reset-xdr-block blk)
  (encode-rpc-msg blk msg)
  (funcall res-encoder blk res)
  (throw 'rpc-manual-reply blk))

(defun rpc-discard-call ()
  "Only valid in the context of a provider SERVER-AUTHENTICATE, SERVER-MODIFY-CALL, 
SERVER-MODIFY-REPLY or a procedure handler. 

Control is immediately returned so that the server will not send a reply to the client. This allows 
authentication providers and procedure handlers to be silent rather than sending replies."
  (frpc2-log :trace "Discard call")
  (throw 'rpc-discard-call nil))

(defun process-rpc-call (server blk msg)
  "Process an RPC call message. The block should have had the message decoded so that its current offset is
at the start of the call arguments. 

SERVER ::= instance of RPC-SERVER.
BLK ::= XDR block initialized with input XDR. Will be cleared and filled with reply XDR on completion.
MSG ::= RPC-MSG call message.

Returns the BLK if a reply should be returned to the client. If the procedure handler or authentication
provider wishes the server to be silent and not send a reply, this function returns NIL."
  (handler-case
      (catch 'rpc-manual-reply
	(catch 'rpc-discard-call 
	  (multiple-value-bind (rverf provider pcxt) (authenticate-rpc-call msg (rpc-server-providers server) blk)
	    (setf (rpc-server-provider-context server) pcxt
		  (rpc-server-auth-flavour server)
		  (opaque-auth-flavour (call-body-auth (xunion-val
							(rpc-msg-body msg)))))
	    (destructuring-bind (fn arg-decoder res-encoder) (find-rpc-handler (rpc-server-programs server) msg)
	      
	      ;; allow provider to modify call
	      (server-modify-call provider pcxt
				  blk
				  (xdr-block-offset blk) (xdr-block-count blk))

	      (let* ((arg (funcall arg-decoder blk))
		     (res (funcall fn server arg)))
		;; reset the block and encode reply msg 
		(reset-xdr-block blk)
		(encode-rpc-msg blk
				(make-rpc-reply (rpc-msg-xid msg)
						:success
						:verf rverf))
		;; encode the result
		(let ((start (xdr-block-offset blk)))
		  (funcall res-encoder blk res)
		  ;; allow the provider to modify the result
		  (server-modify-reply provider pcxt
				       blk
				       start (xdr-block-offset blk)))
		blk)))))
    (xdr-error (e)
      (frpc2-log :error "~A" e)
      ;; xdr decoding error, reply with a garbage args reply
      (reset-xdr-block blk)
      (encode-rpc-msg blk (make-rpc-reply (rpc-msg-xid msg) :garbage-args))
      blk)
    (accept-error (e)
      (frpc2-log :error "~A" e)
      ;; some generic accept error
      (reset-xdr-block blk)
      (encode-rpc-msg blk (make-rpc-reply (rpc-msg-xid msg) (accept-error-stat e)))
      blk)
    (auth-error (e)
      (frpc2-log :error "~A" e)
      ;; the handler signalled an authentication error, encode that sort of reply
      (reset-xdr-block blk)
      (encode-rpc-msg blk (make-rpc-auth-reply (rpc-msg-xid msg) (auth-error-stat e)))
      blk)
    (error (e)
      (frpc2-log :error "~A" e)
      ;; some other sort of error, encode a system error reply 
      (reset-xdr-block blk)
      (encode-rpc-msg blk (make-rpc-reply (rpc-msg-xid msg) :system-error))
      blk)))


