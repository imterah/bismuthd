package main

import (
	"context"
	_ "embed"
	"fmt"
	"net"
	"os"
	"strings"

	"git.greysoh.dev/imterah/bismuthd/client"
	core "git.greysoh.dev/imterah/bismuthd/commons"
	"git.greysoh.dev/imterah/bismuthd/server"
	"github.com/charmbracelet/log"
	"github.com/urfave/cli/v2"
	"tailscale.com/net/socks5"
)

//go:embed ascii.txt
var asciiArt string

func bismuthClientEntrypoint(cCtx *cli.Context) error {
	pubKeyFile, err := os.ReadFile(cCtx.String("pubkey"))

	if err != nil {
		return err
	}

	privKeyFile, err := os.ReadFile(cCtx.String("privkey"))

	if err != nil {
		return err
	}

	pubKey := string(pubKeyFile)
	privKey := string(privKeyFile)

	bismuth, err := client.New(pubKey, privKey)

	if err != nil {
		return err
	}

	routeAllTraffic := cCtx.Bool("route-all-traffic")
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%s", cCtx.String("ip"), cCtx.String("port")))

	if err != nil {
		return err
	}

	socksServer := socks5.Server{
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			ip := addr[:strings.Index(addr, ":")]

			isBismuthTLD := strings.HasSuffix(ip, ".bismuth")

			// There isn't a good way to make the rest of the internet compatible and also have a seperate protocol,
			// so we just do this.
			if isBismuthTLD || routeAllTraffic {
				log.Debugf("Recieved bismuth connection to '%s'. Routing", addr)

				address := addr
				ip := ip
				port := ""

				if isBismuthTLD {
					ip = ip[:strings.LastIndex(addr, ".")]
					port := addr[strings.Index(addr, ":")+1:]

					address = ip + ":" + port
				} else {
					ip = ip[:strings.LastIndex(addr, ":")]
					port := addr[strings.Index(addr, ":")+1:]

					address = ip + ":" + port
				}

				conn, err := net.Dial(network, address)

				if err != nil && err.Error() != "EOF" {
					log.Errorf("TCP connection to '%s:%s' failed", ip, port)
					return nil, err
				}

				conn, err = bismuth.Conn(conn)

				if err != nil && err.Error() != "EOF" {
					log.Errorf("failed to initialize bismuth connection to '%s:%s': '%s'", ip, port, err.Error())
					return nil, err
				}

				return conn, err
			} else {
				conn, err := net.Dial(network, addr)

				if err != nil && err.Error() != "EOF" {
					log.Errorf("TCP connection to '%s' failed", addr)
					return nil, err
				}

				return conn, err
			}
		},
	}

	log.Info("Bismuth client is listening...")

	socksServer.Serve(listener)

	return nil
}

func bismuthServerEntrypoint(cCtx *cli.Context) error {
	relayServers := []string{}

	pubKeyFile, err := os.ReadFile(cCtx.String("pubkey"))

	if err != nil {
		return err
	}

	privKeyFile, err := os.ReadFile(cCtx.String("privkey"))

	if err != nil {
		return err
	}

	pubKey := string(pubKeyFile)
	privKey := string(privKeyFile)

	network := fmt.Sprintf("%s:%s", cCtx.String("source-ip"), cCtx.String("source-port"))

	bismuth, err := server.NewBismuthServer(pubKey, privKey, relayServers, core.XChaCha20Poly1305, func(connBismuth net.Conn) error {
		connDialed, err := net.Dial("tcp", network)

		if err != nil {
			return err
		}

		bismuthBuffer := make([]byte, 65535)
		dialBuffer := make([]byte, 65535)

		go func() {
			defer connDialed.Close()
			defer connBismuth.Close()

			for {
				len, err := connBismuth.Read(bismuthBuffer)

				if err != nil {
					log.Errorf("failed to read from bismuth server: '%s'", err.Error())
					return
				}

				_, err = connDialed.Write(bismuthBuffer[:len])

				if err != nil {
					log.Errorf("failed to write to the proxied server: '%s'", err.Error())
					return
				}
			}
		}()

		go func() {
			defer connDialed.Close()
			defer connBismuth.Close()

			for {
				len, err := connDialed.Read(dialBuffer)

				if err != nil && err.Error() != "EOF" && strings.HasSuffix(err.Error(), "use of closed network connection") {
					log.Errorf("failed to read from proxied server: '%s'", err.Error())
					return
				}

				_, err = connBismuth.Write(dialBuffer[:len])

				if err != nil && err.Error() != "EOF" && strings.HasSuffix(err.Error(), "use of closed network connection") {
					log.Errorf("failed to write to bismuth server: '%s'", err.Error())
					return
				}
			}
		}()

		return nil
	})

	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%s", cCtx.String("dest-ip"), cCtx.String("dest-port")))

	if err != nil {
		return err
	}

	defer listener.Close()

	log.Info("Bismuth server is listening...")

	for {
		conn, err := listener.Accept()
		log.Debugf("Recieved connection from '%s'", conn.RemoteAddr().String())

		if err != nil {
			log.Warn(err.Error())
			continue
		}

		go func() {
			err := bismuth.HandleProxy(conn)

			if err != nil && err.Error() != "EOF" {
				log.Warnf("Connection crashed/dropped during proxy handling: '%s'", err.Error())
			}
		}()
	}
}

func main() {
	fmt.Println(asciiArt)
	fmt.Print("Implementation of the Bismuth protocol\n\n")

	logLevel := os.Getenv("BISMUTHD_LOG_LEVEL")

	if logLevel != "" {
		switch logLevel {
		case "debug":
			log.SetLevel(log.DebugLevel)

		case "info":
			log.SetLevel(log.InfoLevel)

		case "warn":
			log.SetLevel(log.WarnLevel)

		case "error":
			log.SetLevel(log.ErrorLevel)

		case "fatal":
			log.SetLevel(log.FatalLevel)
		}
	}

	app := &cli.App{
		Name:                 "bismuthd",
		Usage:                "reference implementation of the bismuth protocol",
		EnableBashCompletion: true,
		Commands: []*cli.Command{
			{
				Name:    "client",
				Aliases: []string{"c"},
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "pubkey",
						Usage:    "path to PGP public key",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "privkey",
						Usage:    "path to PGP private key",
						Required: true,
					},
					&cli.StringFlag{
						Name:  "ip",
						Usage: "IP to listen on for SOCKS5 server",
						Value: "127.0.0.1",
					},
					&cli.StringFlag{
						Name:  "port",
						Usage: "port to listen on for SOCKS5 server",
						Value: "1080",
					},
					&cli.BoolFlag{
						Name:  "disable-gui",
						Usage: "if set, disables the GUI and automatically accepts all certificates (not recommended)",
					},
					&cli.BoolFlag{
						Name:  "route-all-traffic",
						Usage: "if set, routes all traffic through Bismuth, instead of just IPs that end with the fictional TLD '.bismuth'",
					},
				},
				Usage:  "client for the Bismuth protocol",
				Action: bismuthClientEntrypoint,
			},
			{
				Name:    "server",
				Aliases: []string{"s"},
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "pubkey",
						Usage:    "path to PGP public key",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "privkey",
						Usage:    "path to PGP private key",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "source-ip",
						Usage:    "IP to connect to",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "source-port",
						Usage:    "port to connect to",
						Required: true,
					},
					&cli.StringFlag{
						Name:  "dest-ip",
						Usage: "IP to listen on",
						Value: "0.0.0.0",
					},
					&cli.StringFlag{
						Name:     "dest-port",
						Usage:    "port to listen on",
						Required: true,
					},
				},
				Usage:  "server for the Bismuth protocol",
				Action: bismuthServerEntrypoint,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
