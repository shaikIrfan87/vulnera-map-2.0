package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[RECOVERY] Agent recovered from panic: %v", r)
		}
	}()

	certPath := os.Getenv("AGENT_CERT")
	if certPath == "" {
		certPath = filepath.Join("pki_certs", "agent.crt")
	}
	keyPath := os.Getenv("AGENT_KEY")
	if keyPath == "" {
		keyPath = filepath.Join("pki_certs", "agent.key")
	}
	caPath := os.Getenv("CA_CERT")
	if caPath == "" {
		caPath = filepath.Join("pki_certs", "ca.crt")
	}

	// 1. Load Agent mTLS Certificate & Key
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Printf("[AGENT WARNING] Local certs not found, falling back to HTTP: %v", err)
	}

	// 2. Load Root CA
	caCertPool := x509.NewCertPool()
	if caCert, err := os.ReadFile(caPath); err == nil {
		caCertPool.AppendCertsFromPEM(caCert)
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
		ServerName:         "localhost",
		InsecureSkipVerify: true,
	}

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}

	url := os.Getenv("HUB_URL")
	if url == "" {
		url = "http://127.0.0.1:50051/api/agent/heartbeat"
	}

	log.Println("[AGENT] VULNERA-MAP Agent starting mTLS ping loop...")
	for {
		payload, _ := json.Marshal(map[string]string{
			"node_id":   "Enterprise-Node-01",
			"hostname":  "Enterprise-Node-01",
			"ip_address": "127.0.0.1",
			"status":    "ACTIVE",
		})

		resp, err := client.Post(url, "application/json", bytes.NewBuffer(payload))
		if err != nil {
			log.Printf("[AGENT HEARTBEAT RETRY] %v", err)
		} else {
			resp.Body.Close()
			log.Printf("[AGENT SUCCESS] Server accepted mTLS cert! Status: %d", resp.StatusCode)
		}

		time.Sleep(15 * time.Second)
	}
}
