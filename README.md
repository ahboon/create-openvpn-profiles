# Creating OpenVPN files on demand.

Base script for @NullSec-SIG's HNF 2025. 


### Additional steps on infra
0. Change the `0.0.0.0` to the machine's tailscale IP
1. Run as root :(
2. iptable rules
```bash
sudo iptables -A INPUT -i tailscale0 -p tcp --dport 5000 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 5000 -j DROP
```
