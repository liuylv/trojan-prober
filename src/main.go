package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/liuylv/trojan-prober/src/log"
)

var (
	// Command line parameters
	probeJson  string
	serverAddr string
	serverName string
	logLevel   int

	// Other parameters
	wg          sync.WaitGroup // WaitGroup for synchronizing goroutines
	isTrojan    State          // Indicates whether the server is identified as a Trojan
	startTime   time.Time      // Time to start capturing packets
	finTime     time.Time      // FIN signal time
	finDuration time.Duration  // Time between the start and FIN signal of subsequent probes
)

type ProbeData struct {
	ALPN          string `json:"alpn"`
	BaseContent   string `json:"base_content"`
	RepeatContent string `json:"repeat_content"`
	RepeatNum     int    `json:"repeat_num"`
}

type State int

const (
	Initially     State = iota // 0: Initial state
	Possibly                   // 1: Possibly
	Definitely                 // 2: Definitely
	DefinitelyNot              // 3: Definitely Not
)

type TrojanStatus struct {
	TrojanGFW   State
	TrojanGo    State
	TrojanR     State
	TrojanRS    State
	CaddyTrojan State
}

type HTTPServer struct {
	Nginx    State
	Apache   State
	Caddy    State
	Tomcat   State
	Lighttpd State
	IIS      State
}

var (
	TrojanDetect     = &TrojanStatus{}
	HTTPServerDetect = &HTTPServer{}
)

// Parse command line flags
func parseFlags() {
	flag.StringVar(&probeJson, "probe", "", "Prefix name of the JSON file to be used (required)")
	flag.StringVar(&serverAddr, "serverAddr", "", "Target server address in the format host:port (required)")
	flag.StringVar(&serverName, "serverName", "", "Server name for TLS handshake (required)")
	flag.IntVar(&logLevel, "log", 1, "Log level: 0 for all logs, 1 for crucial logs only")

	flag.Parse()

	log.SetLogLevel(logLevel)

	if probeJson == "" || serverAddr == "" || serverName == "" {
		fmt.Println("Usage of the trojan-prober:")
		flag.PrintDefaults()
		os.Exit(1)
	}
}

// Execute the probe according to the passed probe name and return whether Trojan is detected and the detected Trojan implementation
func executeProbe(probe string) (bool, string) {
	// Load and parse probe JSON data
	probeData, err := loadProbeData(probe)
	if err != nil {
		log.Error(err)
	}

	host, portStr, _ := net.SplitHostPort(serverAddr)
	portInt, _ := strconv.Atoi(portStr)

	if probe == "H1-Close" || probe == "H1-Incomplete" {
		go captureFINPacket("any", host, uint16(portInt), probe)
	}

	// Establish TLS connections
	tlsConn, err := establishTLSConnection(serverAddr, serverName, probeData.ALPN)
	if err != nil {
		handleTLSHandshakeError(err)
		return false, ""
	}
	defer tlsConn.Close()

	// Construct and send request
	probeContent := buildRequest(probeData)
	wg.Add(1)
	go sendRequest(&wg, tlsConn, probeContent)
	wg.Wait()

	// Parse response based on the probe type
	switch probe {
	case "H1-Close":
		parseResponseFromClose(tlsConn, TrojanDetect)
	case "Overbuffer-Incomplete":
		parseResponseFromOver(tlsConn, TrojanDetect)
	case "H1-Incomplete":
		parseResponseFromIncomplete(tlsConn, TrojanDetect)
	case "Short-ALPN-h2":
		parseResponseFromShort(tlsConn, TrojanDetect)
	case "H1-ALPN-h2":
		parseResponseFromALPN(tlsConn, TrojanDetect)
	}

	// If a Trojan is detected, return true and detected trojan type
	if detected, trojanType := isTrojanDetected(TrojanDetect); detected {
		return true, trojanType
	}

	// No Trojan detected, return false and an empty string.
	return false, ""
}

// Load and parse Probe JSON file
func loadProbeData(probe string) (*ProbeData, error) {
	jsonPath := filepath.Join("probe_json", probe+".json")
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %v", jsonPath, err)
	}
	var probeData ProbeData
	if err := json.Unmarshal(jsonData, &probeData); err != nil {
		return nil, fmt.Errorf("failed to parse JSON file %s: %v", jsonPath, err)
	}
	return &probeData, nil
}

// Builds and returns a string request based on the provided ProbeData structure.
func buildRequest(probeData *ProbeData) string {
	baseContent := strings.ReplaceAll(probeData.BaseContent, `\r`, "\r")
	baseContent = strings.ReplaceAll(baseContent, `\n`, "\n")

	repeatContent := strings.ReplaceAll(probeData.RepeatContent, `\r`, "\r")
	repeatContent = strings.ReplaceAll(repeatContent, `\n`, "\n")
	repeatedContent := strings.Repeat(repeatContent, probeData.RepeatNum)

	return baseContent + repeatedContent
}

// Establish TCP and TLS connection
func establishTLSConnection(serverAddr, serverName string, alpn string) (*tls.Conn, error) {
	// Create a TCP connection
	tcpConn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("error connecting to %s: %v", serverAddr, err)
	}

	// Establish a TLS connection
	tlsConn := tls.Client(tcpConn, &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         serverName,
		NextProtos:         []string{alpn},
	})

	// Perform TLS handshake
	if err := tlsConn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("tls Handshake error: %v", err)
	}

	log.Debug("Successfully established TLS connection with %s", tlsConn.RemoteAddr().String())
	return tlsConn, nil
}

// Handle errors that occur during TLS handshake
func handleTLSHandshakeError(err error) {
	if err == nil {
		return
	}
	// Update possible servers states. When facing a probe with ALPN="h2", only Trojan-Go may fail the handshake
	updateState(&TrojanDetect.TrojanGFW, DefinitelyNot)
	updateState(&TrojanDetect.CaddyTrojan, DefinitelyNot)
	updateState(&TrojanDetect.TrojanR, DefinitelyNot)
	updateState(&TrojanDetect.TrojanRS, DefinitelyNot)

	if strings.Contains(err.Error(), "no application protocol") {
		log.Debug(err.Error())
		updateState(&TrojanDetect.TrojanGo, Possibly)
		updateState(&HTTPServerDetect.Nginx, Possibly)
		updateState(&HTTPServerDetect.Lighttpd, Possibly)
	} else if strings.Contains(err.Error(), "server selected unadvertised ALPN protocol") {
		log.Debug(err.Error())
		updateState(&TrojanDetect.TrojanGo, DefinitelyNot)
		updateState(&HTTPServerDetect.Apache, Possibly)
	} else {
		log.Error(err.Error()) //record error and exit
	}
}

// Send a request over a TLS connection and handle potential errors
func sendRequest(wg *sync.WaitGroup, tlsConn net.Conn, probeContent string) {
	defer wg.Done()
	_, err := tlsConn.Write([]byte(probeContent))
	if err != nil {
		if strings.Contains(err.Error(), "broken pipe") {
			log.Debug("Server closed connection after response, possibly due to large data packet.") // normally and not exit
		} else {
			log.Error("Error sending request: %s", err) //record error and exit
		}
		return
	}
}

// Check if a Trojan is detected based on the current Trojan status
func isTrojanDetected(trojanStatus *TrojanStatus) (bool, string) {
	trojanTypes := map[State]string{
		trojanStatus.TrojanGFW:   "Trojan-GFW",
		trojanStatus.TrojanGo:    "Trojan-Go",
		trojanStatus.TrojanR:     "Trojan-R",
		trojanStatus.TrojanRS:    "Trojan-RS",
		trojanStatus.CaddyTrojan: "Caddy-Trojan",
	}

	for state, name := range trojanTypes {
		if state == Definitely {
			return true, name
		}
	}
	return false, ""
}

// Get a list of possible Trojan types based on the given state
func checkTrojanStates(trojanStatus *TrojanStatus, state State) []string {
	possibleTrojanTypes := []string{}
	if trojanStatus.TrojanGFW == state {
		possibleTrojanTypes = append(possibleTrojanTypes, "Trojan-GFW")
	}
	if trojanStatus.TrojanGo == state {
		possibleTrojanTypes = append(possibleTrojanTypes, "Trojan-Go")
	}
	if trojanStatus.TrojanR == state {
		possibleTrojanTypes = append(possibleTrojanTypes, "Trojan-R")
	}
	if trojanStatus.TrojanRS == state {
		possibleTrojanTypes = append(possibleTrojanTypes, "Trojan-RS")
	}
	if trojanStatus.CaddyTrojan == state {
		possibleTrojanTypes = append(possibleTrojanTypes, "Caddy-Trojan")
	}
	return possibleTrojanTypes
}

// Get a list of possible HTTP servers based on the given state
func checkHTTPServers(httpServerStatus *HTTPServer, state State) []string {
	possibleHTTPServers := []string{}
	if httpServerStatus.Nginx == state {
		possibleHTTPServers = append(possibleHTTPServers, "Nginx")
	}
	if httpServerStatus.Apache == state {
		possibleHTTPServers = append(possibleHTTPServers, "Apache")
	}
	if httpServerStatus.Caddy == state {
		possibleHTTPServers = append(possibleHTTPServers, "Caddy")
	}
	if httpServerStatus.Tomcat == state {
		possibleHTTPServers = append(possibleHTTPServers, "Tomcat")
	}
	if httpServerStatus.Lighttpd == state {
		possibleHTTPServers = append(possibleHTTPServers, "Lighttpd")
	}
	if httpServerStatus.IIS == state {
		possibleHTTPServers = append(possibleHTTPServers, "IIS")
	}
	return possibleHTTPServers
}

// Check if all Trojan types are definitely not detected
func allTrojanDefinitelyNot() bool {
	return TrojanDetect.TrojanGFW == DefinitelyNot &&
		TrojanDetect.TrojanGo == DefinitelyNot &&
		TrojanDetect.TrojanR == DefinitelyNot &&
		TrojanDetect.TrojanRS == DefinitelyNot &&
		TrojanDetect.CaddyTrojan == DefinitelyNot
}

// Update the state if the current state is Initially or Possibly
func updateState(currentState *State, newState State) {
	if *currentState == Initially || *currentState == Possibly {
		*currentState = newState
	}
}

// Extract the backend server type from the response string
func extractBackendType(responseStr string) string {
	if strings.Contains(responseStr, "Server:") {
		lines := strings.Split(responseStr, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Server:") {
				return strings.ToLower(strings.TrimSpace(strings.Split(line, ":")[1]))
			}
		}
	} else {
		if strings.Contains(responseStr, "Microsoft-HTTPAPI") || strings.Contains(responseStr, "Microsoft-IIS") {
			return "iis"
		}
		serverTypes := []string{"nginx", "apache", "caddy", "tomcat", "lighttpd"}
		for _, server := range serverTypes {
			if strings.Contains(strings.ToLower(responseStr), strings.ToLower(server)) {
				return strings.ToLower(server)
			}
		}
	}
	return ""
}

// Update the detected backend state to possibly, and the rest to definitely not
func updateHTTPServerState(backendType string, serverStates map[string]*State) {
	if backendType == "" {
		return
	}
	for key, state := range serverStates {
		if strings.Contains(backendType, key) {
			*state = Possibly
		} else {
			*state = DefinitelyNot
		}
	}
}

// Capture FIN packets and log the timing information
func captureFINPacket(device string, targetIP string, targetPort uint16, probeName string) {
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Error("Error opening device: %s", err)
	}
	defer handle.Close()

	filter := fmt.Sprintf("tcp and src host %s and src port %d", targetIP, targetPort)
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Error("Error setting BPF filter: %s", err)
	}

	startTime = time.Now()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if tcp.FIN {
				finTime = time.Now()
				finDuration = finTime.Sub(startTime)
				log.Info("Capture FIN packet at: %s", finDuration)
				break
			}
		}
	}
}

// Print possible Trojans if the target is definitely a Trojan,
func printPossibleTrojan() {
	log.Crucial("The target server is a Trojan")
	trojanTypes := checkTrojanStates(TrojanDetect, Possibly)
	if len(trojanTypes) > 0 {
		log.Crucial("Possible Trojans: %s", strings.Join(trojanTypes, ", "))
	}
}

// Print detected Trojan implementation
func printDetectedTrojan(detectedType string) {
	if detectedType == "Trojan-RS" {
		log.Crucial("The target server is highly likely to be Trojan-RS. It is recommended to perform several tests using the Overbuffer-Incomplete probe to observe its response distribution.")
	} else {
		log.Crucial("The target server is a Trojan, its type is: %s", detectedType)
	}
}

// Print when the target is unlikely to be a Trojan
func printNoTrojanDetected() {
	possibleHTTPServers := checkHTTPServers(HTTPServerDetect, Possibly)
	if len(possibleHTTPServers) > 0 {
		log.Crucial("The target server is not a Trojan. Possible web servers: %s", strings.Join(possibleHTTPServers, ", "))
	} else {
		log.Crucial("The target server is not a Trojan. No possible web server type detected.")
	}
}

// Print when the target is uncertain
func printUncertainDetection() {
	impossibleTrojanTypes := checkTrojanStates(TrojanDetect, DefinitelyNot)
	possibleTrojanTypes := checkTrojanStates(TrojanDetect, Possibly)
	possibleHTTPServers := checkHTTPServers(HTTPServerDetect, Possibly)
	log.Crucial("Uncertain if the target server is a Trojan or HTTPS server.")

	if len(impossibleTrojanTypes) > 0 {
		log.Crucial("Impossible Trojans: %s", strings.Join(impossibleTrojanTypes, ", "))
	}
	if len(possibleTrojanTypes) > 0 {
		log.Crucial("Possible Trojans: %s", strings.Join(possibleTrojanTypes, ", "))
	}
	if len(possibleHTTPServers) > 0 {
		log.Crucial("Possible HTTPS servers: %s", strings.Join(possibleHTTPServers, ", "))
	} else {
		log.Crucial("No identifiable HTTPS servers.")
	}
}

func main() {
	// Parse command line parameters
	parseFlags()

	// Define probe list
	probeList := []string{"H1-Close", "Overbuffer-Incomplete", "Short-ALPN-h2", "H1-ALPN-h2", "H1-Incomplete"}

	// Execute probes
	if probeJson == "all" {
		for _, probe := range probeList {
			log.PrintColoredMessage("----------Executing probe: %s----------", probe)
			detected, detectType := executeProbe(probe)
			if detected {
				printDetectedTrojan(detectType)
				return // Exit if a Trojan is detected
			}
			if isTrojan == Definitely {
				printPossibleTrojan()
				return
			}
			if isTrojan == DefinitelyNot {
				printNoTrojanDetected()
				return
			}
			time.Sleep(3 * time.Second) // Delay before the next probe
		}
	} else {
		executeProbe(probeJson)
	}

	// Checks after probes
	if isTrojan == Definitely {
		printPossibleTrojan()
		return
	}

	if detected, trojanType := isTrojanDetected(TrojanDetect); detected {
		printDetectedTrojan(trojanType)
		return
	} else if allTrojanDefinitelyNot() {
		printNoTrojanDetected()
		return
	} else {
		printUncertainDetection()
	}
}
