package main

import (
	"log"

	"github.com/KumKeeHyun/perisco/perisco/cmd"
)

func main() {
	if err := cmd.New().Execute(); err != nil {
		log.Fatal(err)
	}
}
