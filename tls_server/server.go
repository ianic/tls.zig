package main

import (
	"bufio"
	//"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"os"
	//	"time"
)

func main() {
	log.SetFlags(log.Lshortfile)

	cer, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Println(err)
		return
	}

	config := &tls.Config{Certificates: []tls.Certificate{cer}}
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
	r := bufio.NewReader(conn)
	//for {
	msg, err := r.ReadString('\n')
	if err != nil {
		log.Println(err)
		return
	}

	println(msg)

	// for i := 0; i < 1024; i++ {
	// 	var b bytes.Buffer
	// 	for j := 0; j < i*10; j++ {
	// 		b.WriteString("0123456789")
	// 	}

	// 	n, err := conn.Write(b.Bytes())
	// 	if err != nil {
	// 		log.Println(n, err)
	// 		return
	// 	}
	// }

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
	//time.Sleep(1 * time.Second)
}
