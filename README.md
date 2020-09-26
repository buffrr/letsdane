
# Let's DANE

**Note: Let's DANE is still under development, use at your own risk.**


Let's DANE enables the use of [DANE (DNS Based Authentication of Named Entities)](https://tools.ietf.org/html/rfc6698) in browsers using a simple proxy. It currently supports DANE-EE, and works with self-signed certificates.


<p align="center">
<br>
<br>
<img src="https://github.com/buffrr/letsdane/raw/master/chrome.png" width="320px" alt="Let's DANE Handshake"/>
</p>

<p align="center">
This domain is DNSSEC signed with <a href="https://ed25519.nl/">ed25519</a> on a decentralized name and CA system, handshake.org.   
<br><br>
</p>


<p align="center">
<img src="https://github.com/buffrr/letsdane/raw/master/screenshot.png" width="400px" alt="Let's DANE verified DNSSEC"/><br/>

</p>

<p align="center">
torproject.org with DANE-EE validated certificate
 </p>

## How it works


Let's DANE acts as a trusted intermediary between the browser and DANE enabled sites. It will check if a domain supports it, and generate a certificate on the fly if the authentication was successful. The connection will remain encrypted between you and the end server. If a website doesn't support DANE, its original certificate will be served instead.

For this to work, Let's DANE generates a local certificate authority that must be installed in your browser's certificate store. This CA is used to issue certificates for successful DANE authentications.


## Build from source

You can build the latest version from source for now. binaries in releases are not up to date yet.

make sure you have libunbound installed and run

    git clone https://github.com/buffrr/letsdane.git && cd letsdane/cmd/letsdane
    go build -tags unbound

Note: you can build without unbound, by removing `-tags unbound` and run let's dane with `-skip-dnssec`
this is generally not recommended (you must have a local trusted dnssec resolver). By "local" I mean on your machine!
let's dane will only check the authenticated data flag set by your resolver if `-skip-dnssec` is specified

## Quick Usage

Let's DANE will generate a CA and store it in ~/.letsdane when you start it for the first time. You can use the `-o` option to export the public cert file to a convenient location.


    ./letsdane -o myca.cert

    
* Add Let's DANE proxy to your web browser `127.0.0.1:8080`

* Import the certificate file into your browser certificate store.

By default, letsdane will use the system resolver settings from `/etc/resolv.conf` and fallback to root hints. 
All queries are DNSSEC validated with a hardcoded ICANN 2017 KSK (you can set trust anchor file by setting `-anchor` option)

Use `letsdane -help` to see command line options. 

 Some sites that currently use DANE-EE:
 
* FreeBSD: https://freebsd.org

* Tor Project: https://torproject.org


## Let's DANE with Handshake

You can use [hsd](https://github.com/handshake-org/hsd) or [hnsd](https://github.com/handshake-org/hnsd). Specify address:port of the recursive handshake resolver. You must have it local on your machine to use letsdane securely. 
Add `-skip-dnssec` because it does not use a root ksk (handshake resolver validates dnssec).

Add `-skip-icann` option to prevent the generated CA from issuing certificates for ICANN tlds (recommended)

    ./letsdane -r 127.0.0.1:8585 -o myca.cert -skip-dnssec -skip-icann

Some handshake sites

* https://3b
* https://proofofconcept


## Use of resolvers

Let's DANE uses libunbound to validate DNSSEC, so you don't need to trust any dns provider. 
If you already have a local DNSSEC capable resolver, and you don't want letsdane to validate dnssec for you, 
you can use `-skip-dnssec`  (you should know what you're doing because this can be dangerous!)

If you use `-skip-dnssec`, let's dane will use the Authenticated Data flag.

## Why?

I wanted to try DANE, but no browser currently supports it. It may still be a long way to go for browser support, but if you want to try it now you can!

## Contributing
Contributions are welcome! 



