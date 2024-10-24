package main

import (
	"context"
	_ "embed"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"

	"git.greysoh.dev/imterah/bismuthd/client"
	core "git.greysoh.dev/imterah/bismuthd/commons"
	"git.greysoh.dev/imterah/bismuthd/server"
	"git.greysoh.dev/imterah/bismuthd/signingclient"
	"git.greysoh.dev/imterah/bismuthd/signingserver"
	"github.com/charmbracelet/log"
	"github.com/urfave/cli/v2"
	"tailscale.com/net/socks5"
)

//go:embed ascii.txt
var asciiArt string

func clientEntrypoint(cCtx *cli.Context) error {
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

	log.Debugf("My key fingerprint is: %s", bismuth.PublicKey.GetFingerprint())

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

				conn, returnData, err := bismuth.Conn(conn)

				if err != nil && err.Error() != "EOF" {
					log.Errorf("failed to initialize bismuth connection to '%s:%s': '%s'", ip, port, err.Error())
					return nil, err
				}

				log.Debugf("Server key fingerprint for '%s' is: %s", addr, returnData.ServerPublicKey.GetFingerprint())

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

func serverEntrypoint(cCtx *cli.Context) error {
	signingServers := []string{}

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

	bismuth, err := server.NewBismuthServer(pubKey, privKey, signingServers, core.XChaCha20Poly1305)
	bismuth.HandleConnection = func(connBismuth net.Conn, _ *server.ClientMetadata) error {
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
	}

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

		if err != nil {
			log.Warnf("failed to accept connection: '%s'", err.Error())
			continue
		}

		log.Debugf("Recieved connection from '%s'", conn.RemoteAddr().String())

		go func() {
			err := bismuth.HandleProxy(conn)

			if err != nil && err.Error() != "EOF" {
				log.Warnf("connection crashed/dropped during proxy handling: '%s'", err.Error())
			}
		}()
	}
}

func signingServerEntrypoint(cCtx *cli.Context) error {
	log.Warn("Using the built-in bismuth signing server in production is a horrible idea as it has no validation!")
	log.Warn("Consider writing using a custom solution that's based on the signing server code, rather than the default implementation.")

	signServers := []string{}

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

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%s", cCtx.String("ip"), cCtx.String("port")))

	if err != nil {
		return err
	}

	bismuthServer, err := server.NewBismuthServer(pubKey, privKey, signServers, core.XChaCha20Poly1305)

	if err != nil {
		return nil
	}

	// I'd like to use the SigningServer struct, but I can't really do that
	_, err = signingserver.New(bismuthServer)

	if err != nil {
		return nil
	}

	defer listener.Close()

	log.Info("Bismuth signing server is listening...")

	for {
		conn, err := listener.Accept()

		if err != nil {
			log.Warn(err.Error())
			continue
		}

		log.Debugf("Recieved connection from '%s'", conn.RemoteAddr().String())

		go func() {
			err = bismuthServer.HandleProxy(conn)

			if err != nil && err.Error() != "EOF" {
				log.Warnf("connection crashed/dropped during proxy handling: '%s'", err.Error())
				return
			}
		}()
	}
}

func verifyCert(cCtx *cli.Context) error {
	domainList := strings.Split(cCtx.String("domain-names"), ":")
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

	bismuthClient, err := client.New(pubKey, privKey)

	if err != nil {
		return err
	}

	dialedConn, err := net.Dial("tcp", cCtx.String("signing-server"))

	if err != nil {
		return err
	}

	conn, certResults, err := bismuthClient.Conn(dialedConn)

	if err != nil {
		return err
	}

	if certResults.OverallTrustScore < 50 {
		return fmt.Errorf("overall trust score is below 50% for certificate")
	}

	fmt.Println("Sending signing request to sign server...")

	hasBeenTrusted, err := signingclient.RequestDomainToBeTrusted(conn, domainList, "")

	if hasBeenTrusted {
		fmt.Println("Server has been successfully signed.")
	} else {
		fmt.Println("Server has not been successfully signed.")
		os.Exit(1)
	}

	return nil
}

func signCert(cCtx *cli.Context) error {
	domainList := strings.Split(cCtx.String("domain-names"), ":")
	keyFingerprint, err := hex.DecodeString(cCtx.String("key-fingerprint"))

	if err != nil {
		return err
	}

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

	bismuthClient, err := client.New(pubKey, privKey)

	if err != nil {
		return err
	}

	dialedConn, err := net.Dial("tcp", cCtx.String("signing-server"))

	if err != nil {
		return err
	}

	conn, certResults, err := bismuthClient.Conn(dialedConn)

	if err != nil {
		return err
	}

	if certResults.OverallTrustScore < 50 {
		return fmt.Errorf("overall trust score is below 50% for certificate")
	}

	isTrusted, err := signingclient.IsDomainTrusted(conn, keyFingerprint, domainList)
	fmt.Printf("Certificate trust status: %t\n", isTrusted)

	if !isTrusted {
		os.Exit(1)
	}

	return nil
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
				Action: clientEntrypoint,
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
						Name:  "signing-servers",
						Usage: "servers trusting/\"signing\" the public key. seperated using colons",
					},
					&cli.StringFlag{
						Name:  "domain-names",
						Usage: "domain names the key is authorized to use. seperated using colons",
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
				Action: serverEntrypoint,
			},
			{
				Name:    "test-sign-server",
				Aliases: []string{"tss"},
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
						Usage: "IP to listen on",
						Value: "0.0.0.0",
					},
					&cli.StringFlag{
						Name:  "port",
						Usage: "port to listen on",
						Value: "9090",
					},
					&cli.StringFlag{
						Name:  "domain-names",
						Usage: "domain names the key is authorized to use. seperated using colons",
					},
					&cli.StringFlag{
						Name:  "signing-server",
						Usage: "domain names the key is authorized to use. seperated using colons",
					},
				},
				Usage:  "test signing server for the Bismuth protocol",
				Action: signingServerEntrypoint,
			},
			{
				Name:    "sign-tool",
				Aliases: []string{"st"},
				Subcommands: []*cli.Command{
					{
						Name:    "is-verified",
						Aliases: []string{"i", "iv", "cv"},
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:     "key-fingerprint",
								Usage:    "fingerprint of key",
								Required: true,
							},
							&cli.StringFlag{
								Name:  "pubkey",
								Usage: "path to PGP public key",
							},
							&cli.StringFlag{
								Name:  "privkey",
								Usage: "path to PGP private key",
							},
							&cli.StringFlag{
								Name:     "domain-names",
								Usage:    "domain names the key is authorized to use. seperated using colons",
								Required: true,
							},
							&cli.StringFlag{
								Name:     "signing-server",
								Usage:    "signing server to use",
								Required: true,
							},
						},
						Usage:  "check if a certificate is verified for Bismuth",
						Action: signCert,
					},
					{
						Name:    "verify-cert",
						Aliases: []string{"v", "vc"},
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
								Name:     "domain-names",
								Usage:    "domain names the key is authorized to use. seperated using colons",
								Required: true,
							},
							&cli.StringFlag{
								Name:     "signing-server",
								Usage:    "signing server to use",
								Required: true,
							},
						},
						Usage:  "verifies certificate for Bismuth",
						Action: verifyCert,
					},
				},
				Usage: "signing tool for Bismuth",
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
