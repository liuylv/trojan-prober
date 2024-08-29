package main

import (
	"crypto/tls"
	"strings"
	"time"
	"github.com/liuylv/trojan-prober/src/log"
)

func parseResponseFromShort(tlsConn *tls.Conn, trojanStatus *TrojanStatus) {
	response := make([]byte, 4096)

	// Set a 150-second timer after TLS handshake
	timer150 := time.NewTimer(150 * time.Second)
	defer timer150.Stop()

	// Channel to handle read result
	readDone := make(chan bool)
	readError := false

	// Goroutine to read the server response
	go func() {
		n, err := tlsConn.Read(response)
		if err != nil {
			log.Debug("Error reading from server:%s", err)
			readDone <- true
			readError = true
		}
		log.Info("Response from server:%s", string(response[:n]))
		readDone <- true
	}()

	backendType := ""

	// Wait for either the timer or the read operation to complete
	select {
	case <-timer150.C:
		log.Info("No response within 150 seconds. Target is definitely a Trojan, likely Caddy-Trojan or other Trojans with Caddy backend.")
		isTrojan = Definitely
		updateState(&trojanStatus.CaddyTrojan, Possibly)
		updateState(&trojanStatus.TrojanGFW, Possibly)
		updateState(&trojanStatus.TrojanR, Possibly)
		updateState(&trojanStatus.TrojanRS, Possibly)
		return
	case <-readDone:
		// Response received before the timer expired
		responseStr := string(response[:])
		if !readError { // Read response successfully

			// Check if the response is not in HTTP/1.x format
			if !strings.HasPrefix(responseStr, "HTTP/") {
				for _, state := range []*State{
					&trojanStatus.TrojanGFW, &trojanStatus.TrojanGo,
					&trojanStatus.TrojanR, &trojanStatus.TrojanRS, &trojanStatus.CaddyTrojan,
				} {
					updateState(state, DefinitelyNot)
				}
				log.Info("Response doesn't contain HTTP prefix. Definitely not a Trojan server.")
				isTrojan = DefinitelyNot
				return
			}

			//If the ALPN is h2, the backend is caddy or iis, which supports HTTP/2 by default, and the response is HTTP/1.x, then it must be Trojan
			backendType = extractBackendType(responseStr)
			if backendType == "caddy" || backendType == "iis" {
				isTrojan = Definitely
			}
		}
		updateState(&trojanStatus.CaddyTrojan, DefinitelyNot)
		log.Info("Response received within 150 seconds. Definitely not a Caddy-Trojan.")

		// Update the status of detected backends to Possibly, others to DefinitelyNot
		serverTypes := map[string]*State{
			"nginx":     &HTTPServerDetect.Nginx,
			"apache":    &HTTPServerDetect.Apache,
			"caddy":     &HTTPServerDetect.Caddy,
			"tomcat":    &HTTPServerDetect.Tomcat,
			"lighttpd":  &HTTPServerDetect.Lighttpd,
			"microsoft": &HTTPServerDetect.IIS,
		}
		updateHTTPServerState(backendType, serverTypes)
	}
}
