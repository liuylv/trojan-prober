# trojan-prober
Trojan-Prober is a probing tool which can detect trojan servers.  

========== Build the tool:    
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -tags "full" -o trojan-prober ./src  

========== Usage:    
./trojan-prober -serverAddr [server address] -serverName [server name] -probe [probe name] -log [log level]  
Options:    
    -serverAddr:  Target server address in the format "host:port". (string type, required)  
    -serverName:  Server name for TLS handshake. (string type, required)  
    -probe: Prefix of the probe JSON file. Use a specific name to run that probe, or "all" to run all probes automatically. (string type, required)  
    -log:  Log level: 0 for all logs, 1 for crucial logs only, Default is 1. (int type, optional)  

========== If you use our tool, please cite the paper (under review) at:  

@article{lv2024trojan,  
title={TrojanProbe: Fingerprinting Trojan Tunnel Implementations by Actively Probing Crafted HTTP Requests},  
author={Lv, Liuying and Zhou, Peng},  
journal={under review}, 
year={2024},  
publisher={Elsevier}  
}
