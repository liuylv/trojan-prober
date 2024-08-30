# trojan-prober
Trojan-Prober is a prototype implementation of our TrojanProbe that can be used to actively probe and fingerprint Trojan tunnels by their implementation tricks.  

## How to Build:    
``CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -tags "full" -o trojan-prober ./src``  

## How to Use:    
``./trojan-prober --targetServer [IP/DNS] --targetPort [number] --probe [path to json] --log [0|1] ``   
```
Options:    
    --targetServer: Target server IP address or domain name. (string type, required)   
    --targetPort: Target server port. (string type, required)    
    --probe: Prefix of the probe JSON file. Use a specific name to run that probe, or "all" to run all probes automatically. (string type, required)    
    --log: Log level: 0 for all logs, 1 for crucial logs only, Default is 1. (int type, optional)    
```

### Example:  
For demonstration, please refer to the examples given below:

#### Example 1: 
The case of probing trojan-gfw tunnel with a backend caddy HTTPS server. The probe used here is **./src/probe_json/H1-Close.json**. 

![the case of probing trojan-gfw tunnel with a caddy HTTPS server deployed in the backend](./picture/trojangfw+caddy.png)

#### Example 2: 
The case of probing a real caddy HTTPS server. The probes used here are all the probes located at **./src/probe_json/**.

![the case of probing a real caddy HTTPS server](./picture/caddy.png)

## How to Cite:
#### If you use our tool, please cite the paper as follows:  
```
@article{lv2024trojan,  
title={TrojanProbe: Fingerprinting Trojan Tunnel Implementations by Actively Probing Crafted HTTP Requests},  
author={Lv, Liuying and Zhou, Peng},  
journal={Computers & Security (under review)},   
year={2024},  
publisher={Elsevier}  
}
```
