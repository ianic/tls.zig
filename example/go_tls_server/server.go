package main

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
)

func main() {
	data, err := os.ReadFile("../cert/minica.pem")
	if err != nil {
		panic(err)
	}
	clientCAs := x509.NewCertPool()
	clientCAs.AppendCertsFromPEM(data)

	certificate, err := tls.LoadX509KeyPair("../cert/localhost_ec/cert.pem", "../cert/localhost_ec/key.pem")
	if err != nil {
		panic(err)
	}

	config := &tls.Config{
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAndVerifyClientCert,
		ClientCAs:          clientCAs,
		Certificates:       []tls.Certificate{certificate},
	}
	listener, err := tls.Listen("tcp", ":8443", config)
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
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
