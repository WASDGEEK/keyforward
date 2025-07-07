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
    mode      = flag.String("mode", "encrypt", "Mode: encrypt or decrypt")
    proto     = flag.String("proto", "tcp", "Protocol: tcp or udp")
    laddr     = flag.String("laddr", ":1234", "Local listen port (e.g. :1234)")
    raddr     = flag.String("raddr", "", "Remote forward address (e.g. example.com:80)")
    key       = flag.String("key", "", "AES key (16 bytes)")
    authToken = flag.String("auth", "", "Shared authentication token")
    bindIP    = flag.String("bindip", "0.0.0.0", "IP to bind (default 0.0.0.0)")
)

func main() {
    flag.Parse()

    if *key == "" || len(*key) != 16 {
        log.Fatal("Key must be 16 bytes")
    }

    if *authToken == "" {
        log.Fatal("Authentication token required")
    }

    aead, err := newCipher([]byte(*key))
    if err != nil {
        log.Fatalf("AES init failed: %v", err)
    }

    listenAddr := net.JoinHostPort(*bindIP, strings.TrimPrefix(*laddr, ":"))

    switch strings.ToLower(*proto) {
    case "tcp":
        if *mode == "encrypt" {
            tcpEncrypt(listenAddr, *raddr, aead, *authToken)
        } else {
            tcpDecrypt(listenAddr, *raddr, aead, *authToken)
        }
    case "udp":
        udpForward(listenAddr, *raddr, *mode == "encrypt", aead)
    default:
        log.Fatalf("Unsupported protocol: %s", *proto)
    }
}

func newCipher(key []byte) (cipher.AEAD, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    return cipher.NewGCM(block)
}

// ==================== TCP ====================

func tcpEncrypt(l, r string, aead cipher.AEAD, token string) {
    ln, err := net.Listen("tcp", l)
    if err != nil {
        log.Fatalf("Listen error: %v", err)
    }
    log.Printf("[TCP Encrypt] Listening on %s, forwarding to %s", l, r)

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

            if err := handshake(in, token, true); err != nil {
                log.Println("Client handshake failed:", err)
                return
            }
            if err := handshake(out, token, false); err != nil {
                log.Println("Server handshake failed:", err)
                return
            }

            go io.Copy(out, &decryptReader{conn: in, aead: aead})
            encryptWriter(in, out, aead)
        }(in)
    }
}

func tcpDecrypt(l, r string, aead cipher.AEAD, token string) {
    ln, err := net.Listen("tcp", l)
    if err != nil {
        log.Fatalf("Listen error: %v", err)
    }
    log.Printf("[TCP Decrypt] Listening on %s, forwarding to %s", l, r)

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

            if err := handshake(in, token, true); err != nil {
                log.Println("Client handshake failed:", err)
                return
            }
            if err := handshake(out, token, false); err != nil {
                log.Println("Server handshake failed:", err)
                return
            }

            go io.Copy(out, &decryptReader{conn: in, aead: aead})
            encryptWriter(in, out, aead)
        }(in)
    }
}

// ==================== Encryption Helpers ====================

func encryptAndSend(conn net.Conn, data []byte, aead cipher.AEAD) error {
    nonce := make([]byte, aead.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return err
    }

    ciphertext := aead.Seal(nil, nonce, data, nil)
    total := append(nonce, ciphertext...)

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

// ==================== UDP ====================

func udpForward(l, r string, isEncrypt bool, aead cipher.AEAD) {
    conn, err := net.ListenPacket("udp", l)
    if err != nil {
        log.Fatal("UDP listen failed:", err)
    }
    defer conn.Close()

    log.Printf("[UDP %s] Listening on %s, forwarding to %s", strings.ToUpper(map[bool]string{true: "Encrypt", false: "Decrypt"}[isEncrypt]), l, r)

    buf := make([]byte, 4096)
    for {
        n, addr, err := conn.ReadFrom(buf)
        if err != nil {
            log.Println("UDP read error:", err)
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
            if n < nonceSize {
                continue
            }
            nonce := buf[:nonceSize]
            ct := buf[nonceSize:n]
            data, err = aead.Open(nil, nonce, ct, nil)
            if err != nil {
                log.Println("UDP decrypt failed:", err)
                continue
            }
        }

        dst, err := net.Dial("udp", r)
        if err != nil {
            log.Println("UDP dial error:", err)
            continue
        }
        dst.Write(data)
        dst.Close()

        _ = addr // 可用于响应
    }
}

// ==================== Auth Handshake ====================

func handshake(conn net.Conn, expectedToken string, isServer bool) error {
    buf := make([]byte, 128)

    if isServer {
        // Server: read client's token
        n, err := conn.Read(buf)
        if err != nil {
            return fmt.Errorf("read client token failed: %v", err)
        }
        if string(buf[:n]) != expectedToken {
            return fmt.Errorf("invalid client token")
        }

        // Send back server token
        _, err = conn.Write([]byte(expectedToken))
        return err
    } else {
        // Client: send token
        _, err := conn.Write([]byte(expectedToken))
        if err != nil {
            return err
        }

        // Read server token
        n, err := conn.Read(buf)
        if err != nil {
            return err
        }
        if string(buf[:n]) != expectedToken {
            return fmt.Errorf("invalid server token")
        }
        return nil
    }
}
