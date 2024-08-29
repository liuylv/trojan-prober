package main

import (
	"crypto/tls"
	"github.com/liuylv/trojan-prober/src/log"
	"time"
)

func parseResponseFromIncomplete(tlsConn *tls.Conn, trojanStatus *TrojanStatus) {
	response := make([]byte, 4096)

	// Set timers
	timer150 := time.NewTimer(150 * time.Second)
	timer595 := time.NewTimer(595 * time.Second)
	defer timer150.Stop()
	defer timer595.Stop()

	//Channel to signal response completion
	responseChan := make(chan bool, 1)

	// Goroutine to read the server response
	go func() {
		n, err := tlsConn.Read(response)
		if err != nil {
			log.Debug("Error reading from server:%s", err)
			responseChan <- true
			return
		}
		log.Info("Response from server:%s", string(response[:n]))
		responseChan <- true
	}()

	// Wait for 150s, 595s, or response
	select {
	case <-timer150.C:
		// No response within 150 seconds
		updateState(&TrojanDetect.TrojanGo, Possibly)
		updateState(&TrojanDetect.CaddyTrojan, Possibly)
		log.Info("No response received within 150 seconds. Possible Trojan-Go, Caddy-Trojan, other Trojans with Caddy as the backend, or Caddy.")
		log.Info("Continue waiting for 600s timer")

		select {
		case <-timer595.C:
			// No response within 595 seconds
			log.Info("No response received within 595 seconds. Setting a 10-second timer to check Trojan-RS.")
			timer10 := time.NewTimer(10 * time.Second)
			defer timer10.Stop()

			select {
			case <-timer10.C:
				// No response within 605 seconds
				log.Info("No response received within 605 seconds, Definitely not Trojan-RS.")
				updateState(&TrojanDetect.TrojanRS, DefinitelyNot)
				updateState(&TrojanDetect.TrojanGo, Possibly)
				updateState(&TrojanDetect.CaddyTrojan, Possibly)

			case <-responseChan:
				// Response received between 595-605s
				time.Sleep(2 * time.Second) // Wait for FIN packet capture to update TimeDuration
				if finDuration >= 595*time.Second && finDuration <= 605*time.Second {
					log.Info("Response received within 595-605 seconds. Definitely Trojan-RS.")
					trojanStatus.TrojanRS = Definitely
				} else {
					log.Info("Response received, definitely not Trojan-Go or Caddy-Trojan.")
					updateState(&TrojanDetect.TrojanGo, DefinitelyNot)
					updateState(&TrojanDetect.CaddyTrojan, DefinitelyNot)
				}
			}

		case <-responseChan:
			// Response received between 150-595s
			log.Info("Response received, definitely not Trojan-Go or Caddy-Trojan.")
			updateState(&TrojanDetect.TrojanGo, DefinitelyNot)
			updateState(&TrojanDetect.CaddyTrojan, DefinitelyNot)
		}

	case <-responseChan:
		// Response received before 150s
		log.Info("Response received, definitely not Trojan-Go or Caddy-Trojan.")
		updateState(&TrojanDetect.TrojanGo, DefinitelyNot)
		updateState(&TrojanDetect.CaddyTrojan, DefinitelyNot)
	}
}
