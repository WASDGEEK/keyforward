package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/binary"
    "flag"
    "fmt"
    "io"
    "log"
    "net"
    "strings"
)

var (
    mode  = flag.String("mode", "encrypt", "Mode: encrypt or decrypt")
    proto = flag.String("proto", "tcp", "Protocol: tcp or udp")
    laddr = flag.String("laddr", ":1234", "Local address to listen on")
    raddr = flag.String("raddr", "", "Remote address to forward to")
    key   = flag.String("key", "", "AES key (16 bytes)")
)

// AES stream cipher wrapper
func newCipher(key []byte) (cipher.AEAD, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    return cipher.NewGCM(block)
}

func encryptAndSend(conn net.Conn, data []byte, aead cipher.AEAD) error {
    nonce := make([]byte, aead.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return err
    }

    ciphertext := aead.Seal(nil, nonce, data, nil)
    total := append(nonce, ciphertext...)

    // Length-prefix
    length := make([]byte, 4)
    binary.BigEndian.PutUint32(length, uint32(len(total)))

    _, err := conn.Write(append(length, total...))
    return err
}

func recvAndDecrypt(conn net.Conn, aead cipher.AEAD) ([]byte, error) {
    header := make([]byte, 4)
    if _, err := io.ReadFull(conn, header); err != nil {
        return nil, err
    }
    totalLen := binary.BigEndian.Uint32(header)
    buf := make([]byte, totalLen)
    if _, err := io.ReadFull(conn, buf); err != nil {
        return nil, err
    }

    nonceSize := aead.NonceSize()
    if len(buf) < nonceSize {
        return nil, fmt.Errorf("ciphertext too short")
    }

    nonce := buf[:nonceSize]
    ciphertext := buf[nonceSize:]
    return aead.Open(nil, nonce, ciphertext, nil)
}

// TCP encrypt mode
func tcpEncrypt(l, r string, aead cipher.AEAD) {
    ln, err := net.Listen("tcp", l)
    if err != nil {
        log.Fatalf("Listen error: %v", err)
    }
    log.Printf("Encrypting TCP: %s -> %s", l, r)
    for {
        in, err := ln.Accept()
        if err != nil {
            log.Println("Accept error:", err)
            continue
        }
        go func(in net.Conn) {
            defer in.Close()
            out, err := net.Dial("tcp", r)
            if err != nil {
                log.Println("Dial error:", err)
                return
            }
            defer out.Close()

            go io.Copy(out, &decryptReader{conn: in, aead: aead})
            encryptWriter(in, out, aead)
        }(in)
    }
}

// TCP decrypt mode
func tcpDecrypt(l, r string, aead cipher.AEAD) {
    ln, err := net.Listen("tcp", l)
    if err != nil {
        log.Fatalf("Listen error: %v", err)
    }
    log.Printf("Decrypting TCP: %s -> %s", l, r)
    for {
        in, err := ln.Accept()
        if err != nil {
            log.Println("Accept error:", err)
            continue
        }
        go func(in net.Conn) {
            defer in.Close()
            out, err := net.Dial("tcp", r)
            if err != nil {
                log.Println("Dial error:", err)
                return
            }
            defer out.Close()

            go io.Copy(out, &decryptReader{conn: in, aead: aead})
            encryptWriter(in, out, aead)
        }(in)
    }
}

func encryptWriter(dst net.Conn, src net.Conn, aead cipher.AEAD) {
    buf := make([]byte, 4096)
    for {
        n, err := src.Read(buf)
        if err != nil {
            return
        }
        if err := encryptAndSend(dst, buf[:n], aead); err != nil {
            return
        }
    }
}

type decryptReader struct {
    conn net.Conn
    aead cipher.AEAD
}

func (d *decryptReader) Read(p []byte) (int, error) {
    data, err := recvAndDecrypt(d.conn, d.aead)
    if err != nil {
        return 0, err
    }
    return copy(p, data), nil
}

// UDP (simplified, no length prefix)
func udpForward(l, r string, isEncrypt bool, aead cipher.AEAD) {
    conn, err := net.ListenPacket("udp", l)
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    buf := make([]byte, 4096)
    for {
        n, addr, err := conn.ReadFrom(buf)
        if err != nil {
            log.Println("Read error:", err)
            continue
        }

        var data []byte
        if isEncrypt {
            nonce := make([]byte, aead.NonceSize())
            if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
                continue
            }
            data = append(nonce, aead.Seal(nil, nonce, buf[:n], nil)...)
        } else {
            nonceSize := aead.NonceSize()
            nonce := buf[:nonceSize]
            ct := buf[nonceSize:n]
            data, err = aead.Open(nil, nonce, ct, nil)
            if err != nil {
                log.Println("Decrypt error:", err)
                continue
            }
        }

        dst, err := net.Dial("udp", r)
        if err != nil {
            log.Println("Dial error:", err)
            continue
        }
        dst.Write(data)
        dst.Close()

        // (Optional: write back to sender here if needed)
        _ = addr
    }
}

func main() {
    flag.Parse()

    if *key == "" || len(*key) != 16 {
        log.Fatal("Key must be 16 bytes")
    }

    aead, err := newCipher([]byte(*key))
    if err != nil {
        log.Fatalf("Cipher init error: %v", err)
    }

    switch strings.ToLower(*proto) {
    case "tcp":
        if *mode == "encrypt" {
            tcpEncrypt(*laddr, *raddr, aead)
        } else {
            tcpDecrypt(*laddr, *raddr, aead)
        }
    case "udp":
        udpForward(*laddr, *raddr, *mode == "encrypt", aead)
    default:
        log.Fatal("Unsupported protocol:", *proto)
    }
}
