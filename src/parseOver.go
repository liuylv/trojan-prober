package main

import (
	"crypto/tls"
	"github.com/liuylv/trojan-prober/src/log"
	"io"
	"strings"
	"time"
)

func parseResponseFromOver(tlsConn *tls.Conn, trojanStatus *TrojanStatus) {
	response := make([]byte, 4096)

	// Set a 20-second timer
	timer := time.NewTimer(20 * time.Second)
	defer timer.Stop()

	readDone := make(chan bool)
	exitChan := make(chan struct{})

	// Goroutine to handle reading from the TLS connection
	go func() {
		n, err := tlsConn.Read(response)
		select {
		case <-exitChan:
			return // Exit if the exit signal is received
		default:
			if err != nil {
				if err == io.EOF {
					log.Info("Error reading from server: %s", err)
					updateState(&trojanStatus.TrojanRS, Definitely) // Connection closed prematurely, likely Trojan-RS
				} else {
					log.Debug("Error reading from server: %s", err)
				}
			}
			readDone <- n > 0 // Signal if data was received
		}
	}()

	// Wait for either the timer to expire or data to be read
	select {
	case <-timer.C:
		log.Info("No response received within 20 seconds. Definitely a T-Go.")
		updateState(&trojanStatus.TrojanGo, Definitely)
		close(exitChan) // Signal the goroutine to exit
		return
	case received := <-readDone:
		if received {
			handleResponseFromOver(response, trojanStatus)
		}
	}
}

// Handle and analyze server response
func handleResponseFromOver(response []byte, trojanStatus *TrojanStatus) {
	responseStr := string(response)
	if strings.HasPrefix(responseStr, "HTTP/") {
		log.Info("Response from server:\n%s", responseStr)
		log.Info("Received HTTP response. Definitely not a Trojan-Go.")
		updateState(&trojanStatus.TrojanGo, DefinitelyNot)
		updateState(&trojanStatus.TrojanGFW, Possibly)
		updateState(&trojanStatus.CaddyTrojan, Possibly)
		updateState(&trojanStatus.TrojanR, Possibly)
		updateState(&trojanStatus.TrojanRS, Possibly)

		// Detect server type and update states accordingly
		backendType := extractBackendType(responseStr)
		serverTypes := map[string]*State{
			"nginx":     &HTTPServerDetect.Nginx,
			"apache":    &HTTPServerDetect.Apache,
			"caddy":     &HTTPServerDetect.Caddy,
			"tomcat":    &HTTPServerDetect.Tomcat,
			"lighttpd":  &HTTPServerDetect.Lighttpd,
			"microsoft": &HTTPServerDetect.IIS,
		}
		updateHTTPServerState(backendType, serverTypes)
	} else {
		log.Info("Response from server:\n%s", responseStr)
		log.Info("No HTTP prefix found. Possible Trojan-RS.")
		updateState(&trojanStatus.TrojanRS, Definitely)
	}
}
