package main

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
)

func main() {
	cp := x509.NewCertPool()
	data, err := os.ReadFile("../cert/minica.pem")
	if err != nil {
		panic(err)
	}
	cp.AppendCertsFromPEM(data)

	cer, err := tls.LoadX509KeyPair("../cert/localhost_ec/cert.pem", "../cert/localhost_ec/key.pem")
	if err != nil {
		panic(err)
	}

	config := &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert, // or tls.RequestClientCert,
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
