package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
)

func serverConf() *tls.Config {
	cert := loadPrivK("server")
	pool := x509.NewCertPool()
	pool.AddCert(loadPubK("client"))
	return &tls.Config{
		// Server certificate [server cert-> client]
		Certificates: []tls.Certificate{cert},

		ClientAuth: tls.RequireAndVerifyClientCert,

		// ClientCAs contains the trusted authority that validates incoming client certs
		ClientCAs: pool,
	}
}

func server(ready chan<- string, done <-chan bool, errc chan<- error) {
	printf := func(fm string, v ...interface{}) {
		log.Printf("server: "+fm+"\n", v...)
	}

	fd, err := tls.Listen("tcp", SSocket, serverConf())
	if err != nil {
		printf("%s", err)
		errc <- fmt.Errorf("server: listen: %s", err)
		return
	}

	ready <- fd.Addr().String()
	go func() {
		<-done
		fd.Close()
		errc <- nil
	}()
	for {
		conn, err := fd.Accept()
		select {
		case <-done:
			return
		default:
		}
		addr := "(unknown)"
		if conn != nil {
			addr = conn.RemoteAddr().String()
		}
		if err != nil {
			printf("bad accept from %s (error %s)", addr, err)
			continue
		}
		go func() {
			printf("accepted connection from %s", addr)
			go func() {
				defer conn.Close()
				buf := new(bytes.Buffer)
				io.Copy(buf, conn)
				printf("from client -> %q", buf.String())
			}()
			fmt.Fprint(conn, "hello")
			conn.(*tls.Conn).CloseWrite()
		}()
	}
}
