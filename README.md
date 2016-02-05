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
(define-rpc-server myprog (+myprog-program+ +myprog-version+)
  (null :void :void)
  (proc1 :string proc1-res)
  (proc2 :void proc2-res))
```

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
maintain a table (typically purged on a lease-recently-used basis) of
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
 
## 5. Dependencies
Most dependencies can be found here (http://github.com/fjames86).
 * (fsocket)[http://github.com/fjames86/fsocket] A (hopefully) reliable and portable BSD sockets API
 * (DrX)[http://github.com/fjames86/drx] XDR serializer
 * (pounds)[http://github.com/fjames86/pounds] mmap utilties for debug logging and shared databases.
 * (dragons)[http://github.com/fjames86/dragons] DNS client for name resolution

## 6. License
Licensed under the terms of the MIT license.

Frank James
Febuary 2016.
