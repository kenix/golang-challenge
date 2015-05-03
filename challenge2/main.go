package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/nacl/box"
)

const (
	KeySize   = 32
	NonceSize = 24
)

func genNonce() (*[NonceSize]byte, error) {
	nonce := new([NonceSize]byte)
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	return nonce, nil
}

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[KeySize]byte) io.Reader {
	return &sR{r, priv, pub}
}

type sR struct {
	r       io.Reader
	priv    *[KeySize]byte
	peerPub *[KeySize]byte
}

func (sr *sR) Read(p []byte) (int, error) {
	bs := make([]byte, len(p)+NonceSize+box.Overhead)
	n, err := sr.r.Read(bs)
	if err != nil && err != io.EOF { // TODO timeout
		return 0, err
	}
	//	log.Printf("read %d", n)
	var nonce [NonceSize]byte
	copy(nonce[:], bs[:NonceSize])
	//	log.Printf("nonce: %x", nonce[:])
	m, ok := box.Open(nil, bs[NonceSize:n], &nonce, sr.peerPub, sr.priv)
	if !ok {
		//		log.Printf("%d %t", len(m), m == nil)
		return 0, fmt.Errorf("failed decrypting message")
	}
	copy(p, m)
	return len(m), nil
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[KeySize]byte) io.Writer {
	return &sW{w, priv, pub}
}

type sW struct {
	w       io.Writer
	priv    *[KeySize]byte
	peerPub *[KeySize]byte
}

func (sw *sW) Write(p []byte) (int, error) {
	n, err := genNonce()
	if err != nil {
		return 0, err
	}
	out := box.Seal(n[:], p, n, sw.peerPub, sw.priv)
	//	log.Printf("SW: %d %x", len(out), out)
	return sw.w.Write(out)
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	// perform handshake - (pub) key exchange with peer
	n, err := conn.Write(pub[:])
	if err != nil {
		return nil, err
	}
	if n != KeySize {
		return nil, fmt.Errorf("partial write")
	}
	peerPub := new([KeySize]byte)
	n, err = conn.Read(peerPub[:])
	if err != nil {
		return nil, err
	}
	if n != KeySize {
		return nil, fmt.Errorf("partial read")
	}

	// write encrypts message using peers pub
	// read decrypts message using own priv
	return &sRWC{
		NewSecureReader(conn, priv, peerPub),
		NewSecureWriter(conn, priv, peerPub),
		conn,
	}, nil
}

type sRWC struct {
	io.Reader
	io.Writer
	io.Closer
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	conn, err := l.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	peerPub := new([KeySize]byte)
	n, err := conn.Read(peerPub[:])
	if err != nil {
		return err
	}
	if n != KeySize {
		return fmt.Errorf("illegal key size")
	}

	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	n, err = conn.Write(pub[:])
	if err != nil {
		return err
	}
	if n != KeySize {
		return fmt.Errorf("partial pub key write")
	}

	r := NewSecureReader(conn, priv, peerPub)
	w := NewSecureWriter(conn, priv, peerPub)

	bufSize := 1 << 15 // 32k
	buf := make([]byte, bufSize, bufSize)

	n, err = r.Read(buf)
	if err != nil {
		return err
	}
	_, err = w.Write(buf[:n])
	if err != nil {
		return err
	}

	return nil
}

func main() {
	port := flag.Int("l", 0, "Listen mode. Specify port")
	flag.Parse()

	// Server mode
	if *port != 0 {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()
		log.Fatal(Serve(l))
	}

	// Client mode
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <port> <message>", os.Args[0])
	}
	conn, err := Dial("localhost:" + os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if _, err := conn.Write([]byte(os.Args[2])); err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, len(os.Args[2]))
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", buf[:n])
}
