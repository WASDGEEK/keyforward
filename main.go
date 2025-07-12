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
    "os"
    "strings"
    "time"

    "gopkg.in/yaml.v2"
)

type Config struct {
    Mode      string `yaml:"mode"`
    LAddr     string `yaml:"laddr"`
    RAddr     string `yaml:"raddr"`
    Key       string `yaml:"key"`
    AuthToken string `yaml:"auth"`
    BindIP    string `yaml:"bindip"`
    LogLevel  string `yaml:"loglevel"`
}

var (
    configPath = flag.String("config", "config.yml", "Path to config file")
    cfg        Config
    debug      bool
)

func debugLog(format string, args ...any) {
    if debug {
        log.Printf(format, args...)
    }
}

func main() {
    flag.Parse()

    raw, err := os.ReadFile(*configPath)
    if err != nil {
        log.Fatalf("read config: %v", err)
    }
    if err := yaml.Unmarshal(raw, &cfg); err != nil {
        log.Fatalf("parse config: %v", err)
    }

    if len(cfg.Key) != 16 {
        log.Fatal("key must be 16 bytes")
    }
    if cfg.AuthToken == "" {
        log.Fatal("auth token required")
    }
    if cfg.BindIP == "" {
        cfg.BindIP = "0.0.0.0"
    }
    debug = strings.ToLower(cfg.LogLevel) == "debug"

    aead, err := newCipher([]byte(cfg.Key))
    if err != nil {
        log.Fatalf("cipher init: %v", err)
    }

    listenAddr := net.JoinHostPort(cfg.BindIP, strings.TrimPrefix(cfg.LAddr, ":"))

    if strings.ToLower(cfg.Mode) == "encrypt" {
        go tcpEncrypt(listenAddr, cfg.RAddr, aead, cfg.AuthToken)
        udpForward(listenAddr, cfg.RAddr, true, aead)
    } else {
        go tcpDecrypt(listenAddr, cfg.RAddr, aead, cfg.AuthToken)
        udpForward(listenAddr, cfg.RAddr, false, aead)
    }
}

func newCipher(key []byte) (cipher.AEAD, error) {
    blk, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    return cipher.NewGCM(blk)
}

func tcpEncrypt(l, r string, aead cipher.AEAD, token string) {
    ln, err := net.Listen("tcp", l)
    if err != nil {
        log.Fatalf("listen: %v", err)
    }
    log.Printf("[TCP-Encrypt] %s -> %s", l, r)

    for {
        in, err := ln.Accept()
        if err != nil {
            log.Println("accept:", err)
            continue
        }
        go func(in net.Conn) {
            defer in.Close()
            out, err := net.Dial("tcp", r)
            if err != nil {
                log.Println("dial remote:", err)
                return
            }
            defer out.Close()

            if err := handshake(out, token, false); err != nil {
                log.Println("handshake remote:", err)
                return
            }

            proxyTCPEncrypted(in, out, aead)
        }(in)
    }
}

func tcpDecrypt(l, r string, aead cipher.AEAD, token string) {
    ln, err := net.Listen("tcp", l)
    if err != nil {
        log.Fatalf("listen: %v", err)
    }
    log.Printf("[TCP-Decrypt] %s -> %s", l, r)

    for {
        in, err := ln.Accept()
        if err != nil {
            log.Println("accept:", err)
            continue
        }
        go func(in net.Conn) {
            if err := handshake(in, token, true); err != nil {
                log.Println("handshake client:", err)
                in.Close()
                return
            }

            out, err := net.Dial("tcp", r)
            if err != nil {
                log.Println("dial dest:", err)
                in.Close()
                return
            }
            defer out.Close()
            defer in.Close()

            proxyTCPEncrypted(out, in, aead)
        }(in)
    }
}

func proxyTCPEncrypted(src, dst net.Conn, aead cipher.AEAD) {
    go func() {
        buf := make([]byte, 4096)
        for {
            n, err := src.Read(buf)
            if err != nil {
                log.Println("proxy read err:", err)
                return
            }
            debugLog("Encrypting and forwarding %d bytes", n)
            if err := encryptAndSend(dst, buf[:n], aead); err != nil {
                log.Println("encrypt send err:", err)
                return
            }
        }
    }()

    for {
        data, err := recvAndDecrypt(dst, aead)
        if err != nil {
            log.Println("decrypt recv err:", err)
            return
        }
        debugLog("Decrypted and writing %d bytes", len(data))
        if _, err := src.Write(data); err != nil {
            log.Println("write back err:", err)
            return
        }
    }
}

func encryptAndSend(conn net.Conn, data []byte, aead cipher.AEAD) error {
    nonce := make([]byte, aead.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return err
    }
    ct := aead.Seal(nil, nonce, data, nil)
    packet := append(nonce, ct...)
    hdr := make([]byte, 4)
    binary.BigEndian.PutUint32(hdr, uint32(len(packet)))
    _, err := conn.Write(append(hdr, packet...))
    return err
}

func recvAndDecrypt(conn net.Conn, aead cipher.AEAD) ([]byte, error) {
    hdr := make([]byte, 4)
    if _, err := io.ReadFull(conn, hdr); err != nil {
        return nil, err
    }
    n := binary.BigEndian.Uint32(hdr)
    buf := make([]byte, n)
    if _, err := io.ReadFull(conn, buf); err != nil {
        return nil, err
    }
    nonceSize := aead.NonceSize()
    if len(buf) < nonceSize {
        return nil, fmt.Errorf("ciphertext too short")
    }
    return aead.Open(nil, buf[:nonceSize], buf[nonceSize:], nil)
}

func udpForward(l, r string, encrypt bool, aead cipher.AEAD) {
    conn, err := net.ListenPacket("udp", l)
    if err != nil {
        log.Fatalf("udp listen: %v", err)
    }
    defer conn.Close()
    log.Printf("[UDP-%s] %s <-> %s", map[bool]string{true: "Encrypt", false: "Decrypt"}[encrypt], l, r)

    buf := make([]byte, 4096)

    for {
        n, clientAddr, err := conn.ReadFrom(buf)
        if err != nil {
            log.Println("udp read:", err)
            continue
        }

        go func(data []byte, addr net.Addr) {
            var outData []byte
            if encrypt {
                nonce := make([]byte, aead.NonceSize())
                if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
                    return
                }
                outData = append(nonce, aead.Seal(nil, nonce, data, nil)...)
            } else {
                if len(data) < aead.NonceSize() {
                    return
                }
                nonce := data[:aead.NonceSize()]
                pt, err := aead.Open(nil, nonce, data[aead.NonceSize():], nil)
                if err != nil {
                    return
                }
                outData = pt
            }

            remote, err := net.Dial("udp", r)
            if err != nil {
                log.Println("udp dial:", err)
                return
            }
            defer remote.Close()
            remote.Write(outData)

            remote.SetReadDeadline(time.Now().Add(2 * time.Second))
            n, err := remote.Read(buf)
            if err != nil {
                return
            }

            resp := buf[:n]
            var sendBack []byte
            if encrypt {
                if len(resp) < aead.NonceSize() {
                    return
                }
                nonce := resp[:aead.NonceSize()]
                pt, err := aead.Open(nil, nonce, resp[aead.NonceSize():], nil)
                if err != nil {
                    return
                }
                sendBack = pt
            } else {
                nonce := make([]byte, aead.NonceSize())
                if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
                    return
                }
                sendBack = append(nonce, aead.Seal(nil, nonce, resp, nil)...)
            }

            conn.WriteTo(sendBack, addr)

        }(buf[:n], clientAddr)
    }
}

func handshake(conn net.Conn, token string, server bool) error {
    buf := make([]byte, 128)
    if server {
        n, err := conn.Read(buf)
        if err != nil {
            return fmt.Errorf("read token: %v", err)
        }
        if string(buf[:n]) != token {
            return fmt.Errorf("invalid client token")
        }
        _, err = conn.Write([]byte(token))
        return err
    }
    if _, err := conn.Write([]byte(token)); err != nil {
        return err
    }
    n, err := conn.Read(buf)
    if err != nil {
        return err
    }
    if string(buf[:n]) != token {
        return fmt.Errorf("invalid server token")
    }
    return nil
}
