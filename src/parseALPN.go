package main

import (
	"crypto/tls"
	"strings"
	"github.com/liuylv/trojan-prober/src/log"
)

func parseResponseFromALPN(tlsConn *tls.Conn, trojanStatus *TrojanStatus) {
	// Read server response
	response := make([]byte, 4096)
	n, err := tlsConn.Read(response)
	if err != nil {
		log.Debug("Error reading from server:%s", err)
		return
	}

	responseStr := string(response[:n])
	log.Info("Response from server:\n%s", responseStr)

	// Check if the response contain HTTP prefix
	if !strings.HasPrefix(responseStr, "HTTP/") {
		log.Info("Response doesn't contain HTTP prefix.")
		trojanStatus.CaddyTrojan = Possibly
		for _, state := range []*State{
			&trojanStatus.TrojanGFW, &trojanStatus.TrojanGo,
			&trojanStatus.TrojanR, &trojanStatus.TrojanRS,
		} {
			updateState(state, DefinitelyNot)
		}
		return
	} else {
		log.Info("Response is in HTTP/1.x format.")
		trojanStatus.CaddyTrojan = DefinitelyNot
		for _, state := range []*State{
			&trojanStatus.TrojanGFW, &trojanStatus.TrojanGo,
			&trojanStatus.TrojanR, &trojanStatus.TrojanRS,
		} {
			updateState(state, Possibly)
		}
		// Update the status of detected backends to Possibly, others to DefinitelyNot
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

		//If the ALPN is h2, the backend is caddy or iis, which supports HTTP/2 by default, and the response is HTTP/1.x, then it must be Trojan
		if backendType == "caddy" || backendType == "iis" {
			isTrojan = Definitely
		}
	}
}
