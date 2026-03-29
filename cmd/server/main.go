package main

import (
	"context"
	"log"

	natsauth "github.com/joey0538/nats-jwt-auth"
)

func main() {
	cfg, err := natsauth.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	srv, err := natsauth.NewServer(context.Background(), cfg)
	if err != nil {
		log.Fatal(err)
	}

	if err := srv.Run(); err != nil {
		log.Fatal(err)
	}
}
