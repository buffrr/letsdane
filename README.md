# Go DANE

<a href="https://goreportcard.com/report/github.com/buffrr/godane"><img src="https://goreportcard.com/badge/github.com/buffrr/godane"/></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg"/></a>


**Note: Go DANE is still under development, use at your own risk.**


Go DANE enables the use of [DANE (DNS Based Authentication of Named Entities)](https://tools.ietf.org/html/rfc6698) in browsers using a simple proxy. It currently supports DANE-EE, and works with self-signed certificates.




<p align="center">
<img src="screenshot.png" width="400px" alt="Go DANE verified DNSSEC"/><br/>
</p>

## How it works


Go DANE acts as a middleman between the browser and DANE enabled sites. It will check if a domain supports it, and generate a certificate on the fly if the authentication was successful. The connection will remain encrypted between you and the end server. If a website doesn't support DANE, its original certificate will be served instead.

For this to work, Go DANE generates a local certificate authority that must be installed in your browser's certificate store. This CA is used to issue certificates for successful DANE authentications.
## Usage

You can build it from source using `go build github.com/buffrr/godane/cmd/godane` or download a binary for your OS from [releases](https://github.com/buffrr/godane/releases)
 


    ./godane -dns tls://1.1.1.1

You will be prompted to enter a passphrase. This passphrase is used to encrypt the private key stored on disk.    
    
* Add Go DANE proxy to your web browser `127.0.0.1:8080` for HTTP/HTTPS.

* Import the certificate file `cert.crt` stored at `~/.godane` into your browser.


The easiest way to try it out is to use Firefox because it supports adding a proxy natively and has a built in CA store so that you don't have to add the root CA or proxy to your whole OS (it's still experimental). 

Use `godane -help` to see command line options. 

 Some sites that currently use DANE-EE:
* FreeBSD: https://freebsd.org

* Tor Project: https://torproject.org

* Kumari https://www.kumari.net/


### Go DANE with handshake.org

If you're running a local hsd node listening for dns queries:

    ./godane -dns udp://:53

You can also use [easyhandshake](https://easyhandshake.com) resolver.

    ./godane -dns https://easyhandshake.com:8053
    
    
Note: You can configure hsd to use a different port if 53 is in use.

Some handshake sites

* https://3b
* https://proofofconcept

## Use of resolvers

Go DANE doesn't perform DNSSEC verification by itself. The resolver you specify must be DNSSEC capable. If you have a local validating resolver, you can use udp/tcp. If not, please use a trusted resolver that supports DNSSEC and communicates over a secure channel.

Note: for Go DANE to know the dns response is validated, the resolver must set the  Authenticated Data (AD) flag to true.


## Why?

I wanted to try DANE, but no browser currently supports it. It may still be a long way to go for browser support, but if you want to try it now you can!

## Contributing
Contributions are welcome! 



