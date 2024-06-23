package main

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
)

func main() {
	cp := x509.NewCertPool()
	data, err := ioutil.ReadFile("minica.pem")
	if err != nil {
		panic(err)
	}
	cp.AppendCertsFromPEM(data)

	cer, err := tls.LoadX509KeyPair("server-cert.pem", "server-key.pem")
	if err != nil {
		panic(err)
	}

	config := &tls.Config{
		//ClientAuth: tls.RequestClientCert,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    cp,
		Certificates: []tls.Certificate{cer},
	}
	ln, err := tls.Listen("tcp", ":8443", config)
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			println(err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	_, err := conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\nhello\r\n"))
	if err != nil {
		println(err.Error())
	}
}
