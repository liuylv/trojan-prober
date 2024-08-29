package main

import (
	"crypto/tls"
	"io"
	"time"

	"github.com/liuylv/trojan-prober/src/log"
)

func parseResponseFromClose(tlsConn *tls.Conn, trojanStatus *TrojanStatus) {
	responseTime, backend := parseResponseTime(tlsConn)
	responseDuration := responseTime.Sub(startTime)

	// Wait until FIN is captured
	for finTime.IsZero() {
		time.Sleep(1 * time.Second)
	}

	// Calculate the time difference between response and FIN
	timeDiff := finDuration - responseDuration

	if timeDiff >= 29*time.Second && timeDiff <= 31*time.Second {
		log.Info("Time difference: %f seconds. Definitely a Trojan-GFW.", timeDiff.Seconds())
		trojanStatus.TrojanGFW = Definitely
		return
	}

	log.Info("Time difference: %f seconds. Definitely not a Trojan-GFW server.", timeDiff.Seconds())
	trojanStatus.TrojanGFW = DefinitelyNot
	trojanStatus.TrojanGo = Possibly
	trojanStatus.CaddyTrojan = Possibly
	trojanStatus.TrojanR = Possibly
	trojanStatus.TrojanRS = Possibly

	// Update the status of detected backends to Possibly, others to DefinitelyNot
	serverTypes := map[string]*State{
		"nginx":     &HTTPServerDetect.Nginx,
		"apache":    &HTTPServerDetect.Apache,
		"caddy":     &HTTPServerDetect.Caddy,
		"tomcat":    &HTTPServerDetect.Tomcat,
		"lighttpd":  &HTTPServerDetect.Lighttpd,
		"microsoft": &HTTPServerDetect.IIS,
	}
	updateHTTPServerState(backend, serverTypes)
}

// Parse the response from the server and return the response time and backend type.
func parseResponseTime(tlsConn *tls.Conn) (time.Time, string) {
	response := make([]byte, 4096)
	n, err := tlsConn.Read(response)
	responseTime := time.Now() // Record response time

	if err != nil && err != io.EOF {
		log.Info("Error reading from server:", err)
		return time.Time{}, ""
	}

	responseStr := string(response[:n])
	backendType := extractBackendType(responseStr)
	log.Info("Response from server:\n%s", responseStr)
	log.Info("Capture response at: %s", responseTime)

	return responseTime, backendType
}
