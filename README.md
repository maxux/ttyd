# Core X - ThreeFold Multiplexer

Core X (previously tfmux) is a fork of [ttyd](https://github.com/tsl0922/ttyd),
customized and rewritten to start multiple process and share their interactivity over a web interface.

# Features

- Built on top of Libwebsockets
- API to control behavior
- Fully-featured terminal based on Xterm.js with CJK and IME support
- Graphical ZMODEM integration with lrzsz support
- SSL support based on OpenSSL
- Run any custom command with options
- Basic authentication support and many other custom options
- Multiple process support
- No threads (async)
- Start with chroot environment

# Security

In order to use `corex` as process manager in a container, you can start `corex` with
special `--chroot` flags, when `corex` is ready, it will chroot into that directory and you won't have
access to original directory. With this mechanism, you can start `corex` with all the dependencies needed
and provide chrooted-process access over webui.

# API
Please check the python client (for now). It's quite straightforward.

# Building and Installation

## Build on Linux

### Dependencies for Debian based
> Package libwebsockets-dev version isn't working with this project, we recommand using libwebsocket v2.4.2

```bash
apt-get install cmake g++ pkg-config git libjson-c-dev libssl-dev vim-runtime libz-dev
```

You may also need to compile/install libwebsockets from source if the `libwebsockets-dev` package is outdated

### Dependencies for Gentoo based
```bash
emerge dev-util/cmake dev-vcs/git net-libs/libwebsockets dev-libs/json-c dev-libs/openssl
```

### Libwebsocket Build instruction (needed for Ubuntu)
```
git clone -b v2.4.2 https://github.com/warmcat/libwebsockets
cd libwebsockets && mkdir build && cd build
cmake .. -DLWS_UNIX_SOCK=ON -DLWS_WITHOUT_TESTAPPS=ON -DLWS_WITH_STATIC=OFF
make -j 4 && make install
```

### Core X Build instruction
```
git clone https://github.com/threefoldtech/corex
cd corex && mkdir build && cd build
cmake ..
make
```

You can now use `./corex`

# Usage

## Command-line Options

```
OPTIONS:
    -p, --port              Port to listen (default: 7681, use `0` for random port)
    -i, --interface         Network interface to bind (eg: eth0), or UNIX domain socket path (eg: /var/run/ttyd.sock)
    -c, --credential        Credential for Basic Authentication (format: username:password)
    -u, --uid               User id to run with
    -g, --gid               Group id to run with
    -s, --signal            Signal to send to the command when exit it (default: 1, SIGHUP)
    -r, --reconnect         Time to reconnect for the client in seconds (default: 10)
    -R, --readonly          Do not allow clients to write to the TTY
    -t, --client-option     Send option to client (format: key=value), repeat to add more options
    -O, --check-origin      Do not allow websocket connection from different origin
    -m, --max-clients       Maximum clients to support (default: 0, no limit)
    -o, --once              Accept only one client and exit on disconnection
    -I, --index             Custom index.html path
    -6, --ipv6              Enable IPv6 support
    -S, --ssl               Enable SSL
    -C, --ssl-cert          SSL certificate file path
    -K, --ssl-key           SSL key file path
    -A, --ssl-ca            SSL CA file path for client certificate verification
    -d, --debug             Set log level (default: 7)
    -x, --chroot            Isolate root filesystem
    -v, --version           Print the version and exit
```

## Howto: container based process manager

To use `corex` as process manager (PID 1) inside a container, you need to run `corex` inside a new
namespace (using containerd/runc for example), with all binary dependencies available,
then run `corex --chroot /rootfs` where `rootfs` is the expected root filesystem of the container.

You can then call the API to start a process, the console will be available over the webui and
management available over the API.

## Howto: SSL

Generate SSL CA and self signed server/client certificates:

```bash
# CA certificate (FQDN must be different from server/client)
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 365 -key ca.key -subj "/C=CN/ST=GD/L=SZ/O=Acme, Inc./CN=Acme Root CA" -out ca.crt

# server certificate (for multiple domains, change subjectAltName to: DNS:example.com,DNS:www.example.com)
openssl req -newkey rsa:2048 -nodes -keyout server.key -subj "/C=CN/ST=GD/L=SZ/O=Acme, Inc./CN=localhost" -out server.csr
openssl x509 -req -extfile <(printf "subjectAltName=DNS:localhost") -days 365 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

# client certificate (the p12/pem format may be useful for some clients)
openssl req -newkey rsa:2048 -nodes -keyout client.key -subj "/C=CN/ST=GD/L=SZ/O=Acme, Inc./CN=client" -out client.csr
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt
openssl pkcs12 -export -clcerts -in client.crt -inkey client.key -out client.p12
openssl pkcs12 -in client.p12 -out client.pem -clcerts
```

Then start corex:

```bash
corex --ssl --ssl-cert server.crt --ssl-key server.key --ssl-ca ca.crt bash
```
You may want to test the client certificate verification with `curl`:

```bash
curl --insecure --cert client.p12[:password] -v https://localhost:7681
```

If you don't want to enable client certificate verification, remove the `--ssl-ca` option.
