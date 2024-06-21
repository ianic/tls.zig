package main

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
)

// curl https://localhost:8443 --cacert minica.pem --cert client-cert.pem --key client-key.pem

func main() {
	cp := x509.NewCertPool()
	data, err := ioutil.ReadFile("minica.pem")
	if err != nil {
		panic(err)
	}
	cp.AppendCertsFromPEM(data)

	cer, err := tls.LoadX509KeyPair("client-cert.pem", "client-key.pem")
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
		return
	}

	println(string(buf[:n]))
}
