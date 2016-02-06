# frpc2

This is an ONC-RPC implementation for Common Lisp. Please note that although
some of its code is derived from [frpc](https://github.com/fjames86/frpc), frpc2
is largely a complete rewrite and does not offer any compatibility with it.

## 1. Introduction


## 2. Usage
Please see the DrX documentation on how to define and use the XDR serializer.

### 2.1 Client
Define a client interface:
```
(define-rpc-client myprog (+myprog-program+ +myprog-version+)
  (null :void :void)
  (proc1 :string proc1-res)
  (proc2 :void proc2-res))
```

Use the client: 
```
(with-rpc-client (c udp-client :addr (get-rpc-address 100000 111 "myhost.com"))
  (call-myprog-null c))
```

### 2.2 Server
Define a server program:
```
(defun handle-myprog-null (server arg)
)

(defun handle-myprog-proc1 (server arg)
)

(defun handle-myprog-proc2 (server arg)
)

(define-rpc-server myprog (+myprog-program+ +myprog-version+)
  (null :void :void)
  (proc1 :string proc1-res)
  (proc2 :void proc2-res))
```
Note that the handler functions are expected to have been defined before the server program.

### 2.3 Simple RPC server
Using it is not mandatory but it does offer a set of features that should be suffient for most usages.
Supports:
 * Listens on a set of UDP and TCP ports.
 * Handles registration with the port mapper. 
 * Single thread of control so procedure handlers MUST NOT block.
 * Callback API with timeouts to process replies. This allows the server handlers to make client calls
 and await replies without blocking the main thread. It also allows the handlers to receive callbacks
 on a timeout, e.g. for heartbeating etc. 
 * Non-blocking TCP networking so should scale reasonably well. 
 
### 2.4 Debug logging
By default does not do any debug logging. Can be turned on or off by calling `open-log` and `close-log` respectively.
You can follow the log using `(pounds.log:start-following frpc2:*frpc2-log*)`. Users may write into the log
using `frpc2-log` or `pounds.log:write-message` if they wish to use their own message tag. 

## 3. Authentication providers
There are two classes which should be subclassed: `client-provider` and `server-provider`. There is a set of generic functions which should have methods
defined for them, some of these methods are optional to implement.

### 3.1 Client providers
An RPC client may have one (and only one) authentication provider. Because
of this, the client provider class should store any state it needs directly
in its slots.

Mandatory to implement: 
 * `client-authenticate` : Generate the auth and verf structures to send to the server.
 * `client-verify` : verify the verf structure the server responds with

Optional:
 * `client-modify-call` : Allow the client to change the call argument
 * `client-modify-reply` : Allow the client to change the reply result
 
### 3.2 Server providers
An RPC server may have a list of providers (for each authentication flavour
it wishes to support). As a result the providers cannot store the state for
each authenticated client directly inside the class. Indead, it should
maintain a table (typically purged on a least-recently-used basis) of
context instances for each authenticated client. 

Mandatory:
 * `server-authenticate` : authenticate a client call and generate a reply verifier.

Optional:
 * `server-modify-call` : Allow the server to change the call arg
 * `server-modify-reply` : Allow the server to change the reply result
 
## 4. Notes
The original project, frpc, was written with the intention of writing something
which worked, with other considerations coming much later as they were
encountered. Whereas frpc2 was rewritten with lessons learnt and is
intended to support at least the following:
 * Hopefully better performance by copying and consing less (TODO: actually check this is true by doing some experiments)
 * Much more robust and reliable networking, allowing e.g. UDP multicast and
 non-blocking TCP server codes.
 * Offer lower-level APIs which are transport agnostic as well as higher-level
 functionality which does the networking for ease of use.
 * A consistent authentication provider API which is easy to write plugins for.
 * A low-level RPC server (`rpc-server`) which only processes messages and does no networking.
 * A higher-level RPC server (`simple-rpc-server`) which does networking and other useful things. 
 * The higher-level server offers an API to facilitate making client calls
 from within the server and awaiting replies without blocking.
 * Client API which allows sending calls and receiving replies
 separately, rather than the canonical blocking semantics. 

Some things which might be nice to do but I have no appetite for yet:
 - [ ] Multi-threaded RPC server
 - [ ] Other transports (shared memory, UNIX domain sockets)

### 4.1 Timings
See `test/timing.lisp`.
 * Windows 8.1
 * SBCL 1.3.1 x86-64
 * Calling rpcbind NULL proc on localhost (no authentication)
 * 5000 calls per iteration, averaged over 100 iterations.
 * Server hosted in different image to client.
 * TODO: use sb-profile 
 * TODO: compare against other clients and servers.
 * TODO: Check consing, although we already know frpc2 conses signifiantly less.
 
| Protocol | Client | Server | Seconds per call    |
|----------|--------|--------|---------------------|
| TCP      | frpc   | frpc   | 0.00080 +/- 0.00007 |
| TCP      | frpc   | frpc2  | 0.00034 +/- 0.00001 |
| TCP      | frpc2  | frpc   | 0.00049 +/- 0.00001 |
| TCP      | frpc2  | frpc2  | 0.00023 +/- 0.00001 |
|----------|--------|--------|---------------------|
| UDP      | frpc   | frpc   | 0.00074 +/- 0.00006 |
| UDP      | frpc   | frpc2  | 0.00038 +/- 0.00002 |
| UDP      | frpc2  | frpc   | 0.00055 +/- 0.00001 |
| UDP      | frpc2  | frpc2  | 0.00019 +/- 0.00001 |
|----------|--------|--------|---------------------|

Conclusions:
 * The frpc server takes roughly the same at roughly 0.0005s per call. This suggests the frpc server is the bottleneck.
 * The frpc2 server performs better in all cases. 
 * frpc2 client performs better than the frpc client in all cases.
 * UDP is the winner, but the frpc2 TCP implementation isn't too far off.
 * High variance when using the frpc server means those results are less reliable. Perhaps because it conses much more than frpc2 there is a greater effect from garbage collection? 
 
 
## 5. Dependencies
Most dependencies can be found here (http://github.com/fjames86).
 * [fsocket](http://github.com/fjames86/fsocket) A (hopefully) reliable and portable BSD sockets API
 * [DrX](http://github.com/fjames86/drx) XDR serializer
 * [pounds](http://github.com/fjames86/pounds) mmap utilties for debug logging and shared databases.
 * [dragons](http://github.com/fjames86/dragons) DNS client for name resolution

## 6. License
Licensed under the terms of the MIT license.

Frank James
Febuary 2016.
