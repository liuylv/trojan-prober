# trojan-prober
Trojan-Prober is a probing tool which can detect trojan servers.  

========== Build the tool:    
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -tags "full" -o trojan-prober ./src  

========== Usage:    
./trojan-prober -targetServer [target server] -targetPort [target port] -probe [probe name] -log [log level]    

Options:    
    -targetServer: Target server IP address or domain name. (string type, required)   
    -targetPort:  Target server port. (string type, required)    
    -probe: Prefix of the probe JSON file. Use a specific name to run that probe, or "all" to run all probes automatically. (string type, required)    
    -log:  Log level: 0 for all logs, 1 for crucial logs only, Default is 1. (int type, optional)    

========== Example:  
For specific usage, please refer to the examples given in the picture folder.    
Example1: picture/caddy.png: refers to sending probes automatically to detect the caddy server.  
Example2: picture/trojangfw+caddy1.png, trojangfw+caddy2.png: refer to using a single "H1-Close" to detect the trojan-gfw instance with caddy as the backend.  

========== If you use our tool, please cite the paper (under review) at:  

@article{lv2024trojan,  
title={TrojanProbe: Fingerprinting Trojan Tunnel Implementations by Actively Probing Crafted HTTP Requests},  
author={Lv, Liuying and Zhou, Peng},  
journal={under review},   
year={2024},  
publisher={Elsevier}  
}
