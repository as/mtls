// A self-contained mutually-authenticated TLS client and server

package main

import (
	"log"
	"time"
)

const (
	SAddr = "127.0.0.1"
	CAddr = "127.0.0.2"

	SSocket = SAddr + ":0"
	CSocket = CAddr + ":0"
)

var (

	// gen, secParam = genRSA, "8192"
	// gen, secParam = genRSA, "4096"
	// gen, secParam = genRSA, "2048"
	// gen, secParam = genEC, "P512"

	gen, secParam = genEC, "P256"

	vault = map[string]Envelope{
		"server": genCert("server", "myorg", time.Second*60, SAddr),
		"client": genCert("client", "myorg", time.Second*60, CAddr),
	}
)

type Envelope struct {
	cert, key []byte
}

func main() {

	n := 2
	errc := make(chan error, n) // client and server send final errors on this
	term := make(chan bool)
	kill := make(chan bool)

	first := make(chan bool, 1)
	first <- true
	teardown := func() {
		if <-first {
			close(term)
			close(first)
			log.Println("starting teardown")
		}
	}

	listening := make(chan string)
	go server(listening, term, errc)
	go client(listening, term, errc)

	go func() {
		deadline := time.NewTimer(time.Second * 10)
		select {
		case <-deadline.C:
			teardown()
		case <-term:
		}
		log.Println("sigterm to goroutines; hard shut down in 5s")
		time.Sleep(time.Second * 5)
		close(kill)
	}()

	for n != 0 {
		select {
		case <-kill:
			log.Fatalln("you have been terminated")
		case err := <-errc:
			if err != nil {
				log.Println(err)
			}
			teardown()
			n--
		}
	}

	log.Printf("fin")
}
