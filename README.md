# HTTP script runner

This tool helps you run a tiny HTTP(S) server that will run a given script whenever called properly.

## Installation

Make sure you have `go` installed on your server, then as root run

```
mkdir /opt/http-script-runner
git clone https://github.com/leikir/http-script-runner.git /opt/http-script-runner
cd /opt/http-script-runner
go build http-script-runner.go
mv /opt/http-script-runner/http-script-runner /usr/bin/
```

## Setup

You need:
* a SSL certificate
* a script to run

## Run

Supposing you have an SSL certificate available inside `/etc/ssl/cert`, and your script is something like `/usr/bin/docker-upgrade` then as root run

`http-script-runner -cert=/etc/ssl/cert/fullchain.pem -key=/etc/ssl/cert/privkey.pem -script=/usr/bin/docker-upgrade`

## Bonus: alternative compilation method

If you want to deploy this binary on a Debian-based system you can run this locally then scp the resulting binary file to your server:

`docker run -it --rm -v $(pwd):/opt/http-script-runner golang:1.11.0-stretch go build -o /opt/http-script-runner/http-script-runner /opt/http-script-runner/http-script-runner.go`
