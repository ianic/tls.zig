package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
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

	cer, err := tls.LoadX509KeyPair("../cert/localhost/cert.pem", "../cert/localhost/key.pem")
	if err != nil {
		panic(err)
	}

	config := &tls.Config{
		// ClientAuth:  tls.RequestClientCert,
		ClientCAs:    cp,
		Certificates: []tls.Certificate{cer},
	}

	ln, err := tls.Listen("tcp", ":8443", config)
	if err != nil {
		log.Println(err)
		return
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	f, err := os.Open("pg2600.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	reader := bufio.NewReader(f)
	chunk_size := 1024*32 + 1
	buf := make([]byte, chunk_size)

	for {
		n, err := reader.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Fatal(err)
			}
			break
		}

		n, err = conn.Write(buf[0:n])
		if err != nil {
			log.Println(n, err)
			return
		}
	}
}
