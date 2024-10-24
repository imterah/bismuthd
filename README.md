# Bismuth Protocol [![Go Reference](https://pkg.go.dev/badge/git.greysoh.dev/imterah/bismuthd.svg)](https://pkg.go.dev/git.greysoh.dev/imterah/bismuthd)

The Bismuth protocol is a thin wrapper for any protocol that adds TLS-like features, without being TLS on its own.

## Application
### Building

Git clone this repository and check out a release (except for development, as you probably don't wanna develop on a release version):
```bash
git clone https://git.greysoh.dev/imterah/bismuthd
git checkout v0.1.0
```
Then, build the code:
```bash
go build .
```

### Usage
To get started, you'll need an exported armored public and private key pair.

After that, for usage help, run the help command:
```
./bismuthd help
```
