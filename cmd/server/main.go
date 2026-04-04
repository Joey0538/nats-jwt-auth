package main

import (
	"context"
	"log"

	"github.com/joey0538/nats-jwt-auth/echoserver"
	"github.com/joey0538/nats-jwt-auth/viperconfig"
)

func main() {
	cfg, err := viperconfig.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	srv, err := echoserver.New(context.Background(), cfg)
	if err != nil {
		log.Fatal(err)
	}

	if err := srv.Run(); err != nil {
		log.Fatal(err)
	}
}
