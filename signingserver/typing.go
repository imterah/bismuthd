package signingserver

import "git.greysoh.dev/imterah/bismuthd/server"

type AddVerifyHandlerCallback func(serverAddr string, serverKeyFingerprint string, serverAdvertisedTrustList []string, additionalClientProvidedInfo string) (bool, error)
type VerifyServerHandlerCallback func(serverAddr string, serverKeyFingerprint string, serverDomainList []string) (bool, error)

type BismuthSigningServer struct {
	BismuthServer *server.BismuthServer

	AddVerifyHandler      AddVerifyHandlerCallback
	VerifyServerHandler   VerifyServerHandlerCallback
	builtInVerifyMapStore map[string]string
}
