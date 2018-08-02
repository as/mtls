package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"strconv"
	"time"
)

var twoExp128 = new(big.Int).Lsh(big.NewInt(1), 128)

func genRSA(orderN string) (e crypto.PublicKey, d crypto.PrivateKey) {
	n, err := strconv.Atoi(orderN)
	if err != nil {
		log.Fatalf("genRSA: failed: orderN should be a number: have %s", orderN)
	}

	p, err := rsa.GenerateKey(rand.Reader, n)
	if err != nil {
		log.Fatalf("genRSA: failed: %s", err)
	}
	return &p.PublicKey, p
}

func genEC(curve string) (crypto.PublicKey, crypto.PrivateKey) {
	c := elliptic.Curve(nil)
	switch curve {
	case "P224":
		c = elliptic.P224()
	case "P256":
		c = elliptic.P256()
	case "P384":
		c = elliptic.P256()
	case "P521":
		c = elliptic.P521()
	default:
		log.Fatalf("genEC: unrecognized curve: %q", curve)
	}
	p, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		log.Fatalf("genEC: failed: %s", err)
	}
	return &p.PublicKey, p
}

func genCert(cname, org string, validity time.Duration, hosts ...string) Envelope {
	ca := false
	nb := time.Now()
	na := nb.Add(validity)
	sn := randSN()

	var dns []string
	var addr []net.IP
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			addr = append(addr, ip)
		} else {
			dns = append(dns, h)
		}
	}

	ku := x509.KeyUsageKeyEncipherment // | x509.KeyUsageDigitalSignature
	eku := []x509.ExtKeyUsage{}        // x509.ExtKeyUsageServerAuth

	T := x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   cname,
		},
		IPAddresses:           addr,
		DNSNames:              dns,
		IsCA:                  ca,
		NotBefore:             nb,
		NotAfter:              na,
		KeyUsage:              ku,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: true,
	}

	e, d := gen(secParam)

	der, err := x509.CreateCertificate(rand.Reader, &T, &T, e, d)
	if err != nil {
		log.Fatalf("gen: create: %s", err)
	}

	x509pk := pad(d)

	var certB, keyB bytes.Buffer
	pem.Encode(&certB, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	pem.Encode(&keyB, x509pk)

	return Envelope{certB.Bytes(), keyB.Bytes()}
}

func pad(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		data, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			log.Fatalf("pad: failed: %s", err)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: data}
	}
	return nil
}

func randSN() *big.Int {
	sn, err := rand.Int(rand.Reader, twoExp128)
	if err != nil {
		log.Fatalf("randSN: %s", err)
	}
	return sn
}

func parsePrivK(name string, cert, key []byte) tls.Certificate {
	c, err := tls.X509KeyPair(cert, key)
	if err != nil {
		log.Fatalf("parsePrivK: %q: %s", name, err)
	}
	return c
}
func parsePubK(name string, cert []byte) *x509.Certificate {
	block, _ := pem.Decode([]byte(cert))
	if block == nil {
		log.Fatalf("loadPubK: read %q: failed to parse certificate PEM", name)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("loadPubK: %q parse: %s", name, err)
	}
	return c
}

func loadPrivK(prefix string) tls.Certificate {
	e, ok := vault[prefix]
	if !ok {
		log.Fatalf("loadPrivK: no entry for %q", prefix)
	}
	return parsePrivK(prefix, e.cert, e.key)
}
func loadPubK(prefix string) *x509.Certificate {
	e, ok := vault[prefix]
	if !ok {
		log.Fatalf("loadPubK: no entry for %q", prefix)
	}
	return parsePubK(prefix, e.cert)
}

/*
func loadPrivKFS(prefix string) tls.Certificate {
	cert, err := tls.LoadX509KeyPair(prefix+"/cert.pem", prefix+"/key.pem")
	if err != nil {
		log.Fatalln("loadPrivKFS: %q: %s", prefix, err)
	}
	return cert
}
func loadPubKFS(prefix string) *x509.Certificate {
	data, err := ioutil.ReadFile(prefix + "/cert.pem")
	if err != nil {
		log.Fatalf("loadPubKFS: read %q: %s", prefix, err)
	}
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		log.Fatalf("loadPubKFS: read %q: failed to parse certificate PEM", prefix)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("loadPubKFS: %q parse: %s", prefix, err)
	}
	return cert
}
*/
