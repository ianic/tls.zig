package main

import (
	"crypto/tls"
	"crypto/x509"
	"os"
)

// curl https://localhost:8443 --cacert ../cert/minica.pem --cert ../cert/client-ec/cert.pem --key ../cert/client-ec/key.pem

func main() {
	cp := x509.NewCertPool()
	data, err := os.ReadFile("../cert/minica.pem")
	if err != nil {
		panic(err)
	}
	cp.AppendCertsFromPEM(data)

	cer, err := tls.LoadX509KeyPair("../cert/client_ec/cert.pem", "../cert/client_ec/key.pem")
	if err != nil {
		panic(err)
	}

	conf := &tls.Config{
		Certificates: []tls.Certificate{cer},
		RootCAs:      cp,
	}

	conn, err := tls.Dial("tcp", "localhost:8443", conf)
	if err != nil {
		panic(err)

	}
	defer conn.Close()

	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if err != nil {
		panic(err)
	}

	println(string(buf[:n]))
}
