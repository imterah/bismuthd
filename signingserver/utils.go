package signingserver

import "git.greysoh.dev/imterah/bismuthd/server"

func New(bismuthServer *server.BismuthServer) (*BismuthSigningServer, error) {
	signServer := BismuthSigningServer{
		BismuthServer: bismuthServer,
	}

	if err := signServer.InitializeServer(); err != nil {
		return nil, err
	}

	return &signServer, nil
}
