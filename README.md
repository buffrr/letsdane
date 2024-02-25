# Let's DANE

<a href="https://goreportcard.com/report/github.com/buffrr/letsdane"><img src="https://goreportcard.com/badge/github.com/buffrr/letsdane"/></a>
<a href='https://coveralls.io/github/buffrr/letsdane?branch=master'><img src='https://coveralls.io/repos/github/buffrr/letsdane/badge.svg?branch=master' alt='Coverage Status' /></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg"/></a>

**Note: Let's DANE is still under development, use at your own risk.**

Let's DANE enables the use of [DANE (DNS Based Authentication of Named Entities)](https://tools.ietf.org/html/rfc6698) in browsers and other apps using a lightweight proxy. It currently supports DANE-EE and works with self-signed certificates.

<p align="center">
<img src="https://user-images.githubusercontent.com/41967894/117558143-5fac2200-b02f-11eb-8222-5dc41033b3f4.png" width="450px" alt="Let's DANE verified DNSSEC"/><br/>

</p>

<p align="center">
torproject.org with DANE-EE validated certificate
 </p>

## How it works

Let's DANE acts as a trusted intermediary between the browser and DANE enabled sites. It will check if a domain supports it, and generate a certificate on the fly if the authentication was successful. The connection will remain encrypted between you and the end server. If a website doesn't support DANE, its original certificate will be served instead.

You are essentially trusting your own private certificate authority. You can install it in your browser's CA store to issue certificates for successful DANE authentications.

## Features

- [x] Full DANE-EE support including self-signed certificates ([RFC6698](https://tools.ietf.org/html/rfc6698), [RFC7671](https://tools.ietf.org/html/rfc7671))
- [x] Client-side DNSSEC validation using libunbound
- [x] Prevents downgrade attacks to traditional CAs
- [x] Lightweight DANE tunnels that work with most protocols and with ALPN support.
- [ ] Happy Eyeballs v2 ([RFC8305](https://tools.ietf.org/html/rfc8305))

## Build from source

You can build the latest version from source for now. binaries in releases are not up to date yet.

Go 1.21+ is required. (unbound is optional omit `-tags unbound` to use AD bit only)

```bash
apt install libunbound-dev
git clone https://github.com/buffrr/letsdane.git && cd letsdane/cmd/letsdane
go build -tags unbound
```

## Quick Usage

Let's DANE will generate a CA and store it in `~/.letsdane` when you start it for the first time.
To start the proxy server:

    letsdane -r 1.1.1.1

- Add Let's DANE proxy to your web browser `127.0.0.1:8080` ([Firefox example](https://user-images.githubusercontent.com/41967894/117558156-8f5b2a00-b02f-11eb-98ba-91ce8a9bdd4a.png))

- Import the certificate file into your browser certificate store ([Firefox example](https://user-images.githubusercontent.com/41967894/117558164-a7cb4480-b02f-11eb-93ed-678f81f25f2e.png)). You can use `letsdane -o myca.crt` to export the public cert file to a convenient location.

If you don't specify a resolver, letsdane will use the system resolver settings from `/etc/resolv.conf` and fallback to root hints.
If letsdane is compiled with libunbound, all queries are DNSSEC validated with a hardcoded ICANN 2017 KSK (you can set trust anchor file by setting `-anchor` option)

Use `letsdane -help` to see command line options.

### DANE Tools

- danectl: <https://raf.org/danectl> (helper tool for certbot & letsencrypt)
- other: <https://www.huque.com/pages/tools.html> (various DANE tools)

## Docker

### Building an image

To build a Docker image run:

    git clone https://github.com/buffrr/letsdane
    cd letsdane && docker build -t letsdane .

### Running a container

To start a container with proxy on port `8080` with certs in the dane directory run:

    docker run --name letsdane -dp 127.0.0.1:8080:8080 \
      -v "$(pwd)"/dane:/root/.letsdane \
      --restart unless-stopped \
      letsdane -verbose

## Threat Model

The proxy is intended to be installed locally on your machine, and the generated CA should only be used on that machine. letsdane assumes that your user account is secure (even without letsdane, your user account must not be compromised to be able to use a browser securely)

## Use of resolvers

letsdane uses libunbound to validate DNSSEC, so you don't need to trust any dns provider.
If you already have a local DNSSEC capable resolver, and you don't want letsdane to validate dnssec for you,
you can use `-skip-dnssec`  (you should know what you're doing because this can be dangerous!)

If you use `-skip-dnssec`, letsdane will use the Authenticated Data flag.

## Why?

I wanted to try DANE, but no browser currently supports it. It may still be a long way to go for browser support, but if you want to try it now you can!

## Contributing

Contributions are welcome!

## Credits

Thanks to the awesome [miekg/dns](https://github.com/miekg/dns) package.

Even though TLS proxies are not new, the [GNU Naming System](https://gnunet.org/en/gns.html) has prior art on this since they also use a TLS proxy to make their domains work in other applications, but their naming system is very different from traditional DNS.
