package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
)

func clientConf() *tls.Config {
	cert := loadPrivK("client")
	pool := x509.NewCertPool()
	pool.AddCert(loadPubK("server"))
	return &tls.Config{
		// Client presents this to the server
		Certificates: []tls.Certificate{cert},

		// RootCAs are used by clients to validate server certificates. They
		// are the public keys of trusted root certificate authorities.
		RootCAs: pool,

		// ServerName used to verify the server's hostname on returned certificates
		// It can also be an IP address.
		ServerName: SAddr,
	}
}

func client(ready <-chan string, done <-chan bool, errc chan<- error) {
	printf := func(fm string, v ...interface{}) {
		log.Printf("client: "+fm+"\n", v...)
	}
	esend := func(fm string, v ...interface{}) {
		errc <- fmt.Errorf("client: "+fm, v...)
	}

	raddr := <-ready
	if raddr == "" {
		esend("error on the server side")
		return
	}
	printf("dial  -> %s", raddr)
	lip, err := net.ResolveTCPAddr("tcp", CSocket)
	if err != nil {
		esend("failed to resolve local IP: %s", err)
		return
	}
	d := &net.Dialer{
		LocalAddr: lip,
	}
	conn, err := tls.DialWithDialer(d, "tcp", raddr, clientConf())
	laddr := "(unknown)"
	if conn != nil {
		laddr = conn.LocalAddr().String()
	}
	printf("conn %s -> %s", laddr, raddr)
	if err != nil {
		esend("error dialing conn from %s -> %s (error %s)", laddr, raddr, err)
		return
	}
	go func() {
		defer conn.Close()
		buf := new(bytes.Buffer)
		_, err = io.Copy(buf, conn)
		printf("from server -> %q", buf.String())
		errc <- err
	}()
	fmt.Fprintf(conn, "hi")
	conn.CloseWrite()

	<-done
}
