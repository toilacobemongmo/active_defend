"""
Module: mini_ssh_honeypot.py
Mục đích: SSH Honeypot tương tác độ chân thực cao (High-Fidelity Virtual SSH Honeypot).
Mô phỏng chân thực 100% cơ chế của Cowrie:
- Hệ thống tệp tin ảo đa tầng (Virtual File System - VFS): /root, /etc, /var, /home, /proc, /tmp
- Điều hướng thư mục thực sự: cd, pwd, ls -la, mkdir, touch, rm, cp, mv, echo, cat
- Hỗ trợ phím TAB (Tab Autocomplete) gợi ý tên file, thư mục và câu lệnh
- Hỗ trợ phím Mũi tên Lên/Xuống (Command History Up/Down)
- Đổi prompt linh hoạt theo thư mục: root@ubuntu-srv:/var/backups#
- Gài 3 lớp bẫy Honeytokens (AWS credentials, bash_history, db_backup.sql)
- Cơ chế Tarpit socket giam lỏng kẻ tấn công (3s/byte)
"""

from datetime import datetime ,timezone
import json
import os
import re
import socket
import sys
import threading
import time
from typing import Dict ,List ,Optional ,Tuple
import paramiko


def get_outbound_ip ()->str :
    """Tự động xác định địa chỉ IP card mạng của Honeypot để gài vào Honeytokens."""
    try :
        s =socket .socket (socket .AF_INET ,socket .SOCK_DGRAM )
        s .connect (("8.8.8.8",80 ))
        ip =s .getsockname ()[0 ]
        s .close ()
        return ip
    except Exception :
        return "127.0.0.1"


class VirtualFileSystem :
    """Hệ thống tệp tin ảo trong bộ nhớ mô phỏng Linux VFS chuẩn Cowrie."""
    def __init__ (self ,host_ip :Optional [str ]=None ):
        self .host_ip =host_ip or get_outbound_ip ()
        self .fs :Dict [str ,Dict ]={
        "/":{"type":"dir","perm":"drwxr-xr-x","owner":"root","group":"root"},
        "/bin":{"type":"dir","perm":"drwxr-xr-x","owner":"root","group":"root"},
        "/boot":{"type":"dir","perm":"drwxr-xr-x","owner":"root","group":"root"},
        "/dev":{"type":"dir","perm":"drwxr-xr-x","owner":"root","group":"root"},
        "/etc":{"type":"dir","perm":"drwxr-xr-x","owner":"root","group":"root"},
        "/home":{"type":"dir","perm":"drwxr-xr-x","owner":"root","group":"root"},
        "/home/ubuntu":{"type":"dir","perm":"drwxr-xr-x","owner":"ubuntu","group":"ubuntu"},
        "/lib":{"type":"dir","perm":"drwxr-xr-x","owner":"root","group":"root"},
        "/media":{"type":"dir","perm":"drwxr-xr-x","owner":"root","group":"root"},
        "/mnt":{"type":"dir","perm":"drwxr-xr-x","owner":"root","group":"root"},
        "/opt":{"type":"dir","perm":"drwxr-xr-x","owner":"root","group":"root"},
        "/proc":{"type":"dir","perm":"dr-xr-xr-x","owner":"root","group":"root"},
        "/root":{"type":"dir","perm":"drwx------","owner":"root","group":"root"},
        "/root/.aws":{"type":"dir","perm":"drwxr-xr-x","owner":"root","group":"root"},
        "/run":{"type":"dir","perm":"drwxr-xr-x","owner":"root","group":"root"},
        "/sbin":{"type":"dir","perm":"drwxr-xr-x","owner":"root","group":"root"},
        "/srv":{"type":"dir","perm":"drwxr-xr-x","owner":"root","group":"root"},
        "/sys":{"type":"dir","perm":"dr-xr-xr-x","owner":"root","group":"root"},
        "/tmp":{"type":"dir","perm":"drwxrwxrwt","owner":"root","group":"root"},
        "/usr":{"type":"dir","perm":"drwxr-xr-x","owner":"root","group":"root"},
        "/var":{"type":"dir","perm":"drwxr-xr-x","owner":"root","group":"root"},
        "/var/backups":{"type":"dir","perm":"drwxr-xr-x","owner":"root","group":"root"},
        "/var/log":{"type":"dir","perm":"drwxr-xr-x","owner":"root","group":"root"},
        "/var/www":{"type":"dir","perm":"drwxr-xr-x","owner":"root","group":"root"},
        }
        self ._init_default_files ()

    def _init_default_files (self ):

        self .fs ["/root/.aws/credentials"]={
        "type":"file",
        "perm":"-rw-------",
        "owner":"root",
        "group":"root",
        "content":(
        "[default]\n"
        "aws_access_key_id = AKIAIOSFODNN7CANARYAWS\n"
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "# Honeytoken Canary Beacon (HTTP Verification Endpoint):\n"
        f"# http://{self .host_ip }:8080/canary/aws_verify?token=canary_aws_8892\n"
        "region = ap-southeast-1\n"
        ),
        }


        self .fs ["/root/.bash_history"]={
        "type":"file",
        "perm":"-rw-------",
        "owner":"root",
        "group":"root",
        "content":(
        "ls -la\n"
        "cd /var/backups\n"
        "cat db_backup.sql\n"
        "# Download emergency hotfix patch for critical zero-day:\n"
        f"curl -s http://{self .host_ip }:8080/canary/patch.sh | bash\n"
        "history -c\n"
        ),
        }


        db_dump =(
        "-- Enterprise Production Database Backup 2026\n"
        "CREATE DATABASE enterprise_core;\n"
        "USE enterprise_core;\n"
        "INSERT INTO users VALUES ('superadmin', '$2a$12$e8rO2zM4vL1kH...', 'admin@corp.internal');\n"
        "INSERT INTO users VALUES ('db_backup_svc', '$2a$12$9qQ8bV1vP8mK7...', 'svc@corp.internal');\n"
        "-- Internal Single-Sign-On (SSO) Portal:\n"
        f"-- http://{self .host_ip }:8080/canary/db_verify?token=canary_sql_9941\n"
        )
        self .fs ["/root/db_backup.sql"]={
        "type":"file",
        "perm":"-rw-r--r--",
        "owner":"root",
        "group":"root",
        "content":db_dump ,
        }
        self .fs ["/var/backups/db_backup_2026.sql"]={
        "type":"file",
        "perm":"-rw-r--r--",
        "owner":"root",
        "group":"root",
        "content":db_dump ,
        }


        self .fs ["/etc/passwd"]={
        "type":"file",
        "perm":"-rw-r--r--",
        "owner":"root",
        "group":"root",
        "content":(
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
        "sync:x:4:65534:sync:/bin:/bin/sync\n"
        "games:x:5:60:games:/usr/games:/usr/sbin/nologin\n"
        "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n"
        "sshd:x:107:65534::/run/sshd:/usr/sbin/nologin\n"
        "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
        ),
        }
        self .fs ["/etc/shadow"]={
        "type":"file",
        "perm":"-rw-------",
        "owner":"root",
        "group":"shadow",
        "content":(
        "root:$6$rounds=4096$salt$Z1Lp...:19245:0:99999:7:::\n"
        "ubuntu:$6$rounds=4096$salt$W8tM...:19245:0:99999:7:::\n"
        ),
        }
        self .fs ["/etc/hostname"]={
        "type":"file",
        "perm":"-rw-r--r--",
        "owner":"root",
        "group":"root",
        "content":"ubuntu-srv\n",
        }
        self .fs ["/etc/hosts"]={
        "type":"file",
        "perm":"-rw-r--r--",
        "owner":"root",
        "group":"root",
        "content":"127.0.0.1 localhost\n127.0.1.1 ubuntu-srv\n",
        }
        self .fs ["/etc/issue"]={
        "type":"file",
        "perm":"-rw-r--r--",
        "owner":"root",
        "group":"root",
        "content":"Ubuntu 22.04.3 LTS \\n \\l\n",
        }
        self .fs ["/etc/os-release"]={
        "type":"file",
        "perm":"-rw-r--r--",
        "owner":"root",
        "group":"root",
        "content":(
        "PRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\n"
        "NAME=\"Ubuntu\"\n"
        "VERSION_ID=\"22.04\"\n"
        "VERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\n"
        "ID=ubuntu\n"
        "ID_LIKE=debian\n"
        ),
        }
        self .fs ["/proc/cpuinfo"]={
        "type":"file",
        "perm":"-r--r--r--",
        "owner":"root",
        "group":"root",
        "content":(
        "processor\t: 0\n"
        "vendor_id\t: GenuineIntel\n"
        "cpu family\t: 6\n"
        "model\t\t: 63\n"
        "model name\t: Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz\n"
        "stepping\t: 2\n"
        "cpu MHz\t\t: 2400.046\n"
        "cache size\t: 30720 KB\n"
        ),
        }
        self .fs ["/proc/meminfo"]={
        "type":"file",
        "perm":"-r--r--r--",
        "owner":"root",
        "group":"root",
        "content":(
        "MemTotal:        4018612 kB\n"
        "MemFree:         2140516 kB\n"
        "MemAvailable:    2891404 kB\n"
        "Buffers:          124932 kB\n"
        "Cached:           918420 kB\n"
        ),
        }

    def resolve_path (self ,cwd :str ,target :str )->str :
        """Chuẩn hóa đường dẫn tương đối hoặc tuyệt đối."""
        if not target or target =="~":
            return "/root"
        if target .startswith ("~/"):
            target ="/root"+target [1 :]
        if not target .startswith ("/"):
            if cwd =="/":
                combined ="/"+target
            else :
                combined =f"{cwd }/{target }"
        else :
            combined =target


        parts =[]
        for p in combined .split ("/"):
            if not p or p ==".":
                continue
            if p =="..":
                if parts :
                    parts .pop ()
            else :
                parts .append (p )
        return "/"+"/".join (parts )

    def is_dir (self ,path :str )->bool :
        norm =path .rstrip ("/")if path !="/"else "/"
        return norm in self .fs and self .fs [norm ]["type"]=="dir"

    def is_file (self ,path :str )->bool :
        norm =path .rstrip ("/")if path !="/"else "/"
        return norm in self .fs and self .fs [norm ]["type"]=="file"

    def exists (self ,path :str )->bool :
        norm =path .rstrip ("/")if path !="/"else "/"
        return norm in self .fs

    def list_dir (self ,path :str )->List [Tuple [str ,Dict ]]:
        """Liệt kê các mục trực tiếp nằm trong thư mục."""
        norm =path .rstrip ("/")if path !="/"else "/"
        results =[]
        prefix =norm if norm !="/"else ""
        for p ,info in self .fs .items ():
            if p ==norm :
                continue
            if p .startswith (prefix +"/"):
                sub =p [len (prefix )+1 :]
                if "/"not in sub :
                    results .append ((sub ,info ))
        return sorted (results ,key =lambda x :x [0 ])

    def read_file (self ,path :str )->Optional [str ]:
        norm =path .rstrip ("/")
        if norm in self .fs and self .fs [norm ]["type"]=="file":
            return self .fs [norm ].get ("content","")
        return None

    def write_file (self ,path :str ,content :str ,append :bool =False ):
        norm =path .rstrip ("/")
        if norm in self .fs and self .fs [norm ]["type"]=="file"and append :
            self .fs [norm ]["content"]+=content
        else :
            self .fs [norm ]={
            "type":"file",
            "perm":"-rw-r--r--",
            "owner":"root",
            "group":"root",
            "content":content ,
            }

    def mkdir (self ,path :str )->bool :
        norm =path .rstrip ("/")
        if norm not in self .fs :
            self .fs [norm ]={
            "type":"dir",
            "perm":"drwxr-xr-x",
            "owner":"root",
            "group":"root",
            }
            return True
        return False

    def remove (self ,path :str )->bool :
        norm =path .rstrip ("/")
        if norm in self .fs :

            to_del =[p for p in self .fs if p ==norm or p .startswith (norm +"/")]
            for p in to_del :
                del self .fs [p ]
            return True
        return False


class HoneypotSSHServer (paramiko .ServerInterface ):
    def __init__ (self ,client_ip :str ,log_callback ,is_ip_blocked_func ):
        self .client_ip =client_ip
        self .log_callback =log_callback
        self .is_ip_blocked_func =is_ip_blocked_func
        self .event =threading .Event ()
        self .authenticated_user =""
        self .session_id =f"sess_{int (time .time ()*1000 )%100000 }"

    def check_auth_password (self ,username ,password ):
        print (f"\n[*] [SSH Honeypot] Attacker IP {self .client_ip } vừa thử đăng nhập | User: '{username }' | Password: '{password }'")


        if self .is_ip_blocked_func (self .client_ip ):
            print (f"[-] [SSH Honeypot] TỪ CHỐI IP {self .client_ip } do đang bị SOAR Firewall khóa cứng!")
            return paramiko .AUTH_FAILED


        if hasattr (self ,"is_tarpitted_func")and self .is_tarpitted_func (self .client_ip ):
            print (f"[TARPIT] Đang giam lỏng IP {self .client_ip }: Trì hoãn phản hồi 3 giây...")
            time .sleep (3 )


        valid_accounts ={
        "ubuntu":"1234567",
        "root":"monkey"
        }


        if username in valid_accounts and password ==valid_accounts [username ]:
            print (f"[+] [SSH Honeypot] Đăng nhập THÀNH CÔNG (Cấp shell Linux giả lập cho IP {self .client_ip })")
            self .authenticated_user =username
            self .log_callback ({
            "eventid":"cowrie.login.success",
            "src_ip":self .client_ip ,
            "username":username ,
            "password":password ,
            "session":self .session_id ,
            "timestamp":datetime .now (timezone .utc ).isoformat (),
            })
            return paramiko .AUTH_SUCCESSFUL
        else :
            print (f"[-] [SSH Honeypot] Đăng nhập THẤT BẠI cho IP {self .client_ip } (Ghi nhận hành vi Brute Force)")
            self .log_callback ({
            "eventid":"cowrie.login.failed",
            "src_ip":self .client_ip ,
            "username":username ,
            "password":password ,
            "timestamp":datetime .now (timezone .utc ).isoformat (),
            })
            return paramiko .AUTH_FAILED

    def check_channel_request (self ,kind ,chanid ):
        if kind =="session":
            return paramiko .OPEN_SUCCEEDED
        return paramiko .OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request (self ,channel ,term ,width ,height ,pixelwidth ,pixelheight ,modes ):
        return True

    def check_channel_shell_request (self ,channel ):
        self .event .set ()
        return True


class CowrieSessionHandler :
    """Xử lý phiên tương tác Shell đầy đủ: VFS, cd, ls, Tab autocomplete, History."""
    KNOWN_COMMANDS =[
    "whoami","id","uname","pwd","ls","cd","cat","ps","top","touch",
    "mkdir","rm","cp","mv","echo","chmod","curl","wget","ifconfig",
    "ip","netstat","ss","history","clear","help","ping","sudo","exit",
    "logout","which","whereis","head","tail","more","less","grep",
    "nano","vi","vim",
    ]

    def __init__ (self ,channel ,client_ip :str ,session_id :str ,username :str ,log_event_func ,host_ip :Optional [str ]=None ):
        self .channel =channel
        self .client_ip =client_ip
        self .session_id =session_id
        self .username =username or "root"
        self .log_event =log_event_func
        self .vfs =VirtualFileSystem (host_ip =host_ip )
        self .cwd ="/root"
        self .history :List [str ]=[]
        self .history_index =0

    def get_prompt (self )->str :
        display_dir ="~"if self .cwd =="/root"else self .cwd
        return f"{self .username }@ubuntu-srv:{display_dir }# "

    def run (self ):

        banner =(
        "\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)\r\n\r\n"
        " * Documentation:  https://help.ubuntu.com\r\n"
        " * Management:     https://landscape.canonical.com\r\n"
        " * Support:        https://ubuntu.com/advantage\r\n\r\n"
        f"System information as of {datetime .now ().strftime ('%a %b %d %H:%M:%S UTC %Y')}\r\n"
        "  System load:  0.08, 0.03, 0.01      Processes:           112\r\n"
        "  Usage of /:   18.4% of 38.70GB      Users logged in:     1\r\n"
        "  Memory usage: 22%                   IPv4 address for eth0: 10.0.3.15\r\n\r\n"
        "Last login: Fri Oct  2 08:44:12 2026 from 192.168.1.100\r\n"
        )
        self .channel .send (banner )
        self .channel .send (self .get_prompt ())

        cmd_buffer =""
        escape_seq =""

        while self .channel .active :
            try :
                data =self .channel .recv (1024 )
            except Exception :
                break
            if not data :
                break

            i =0
            while i <len (data ):
                b =data [i ]
                char =chr (b )
                i +=1


                if escape_seq :
                    escape_seq +=char
                    if escape_seq =="\x1b[A":
                        escape_seq =""
                        if self .history and self .history_index >0 :
                            self .history_index -=1
                            prev_cmd =self .history [self .history_index ]

                            self .channel .send ("\b \b"*len (cmd_buffer ))
                            cmd_buffer =prev_cmd
                            self .channel .send (cmd_buffer )
                        continue
                    elif escape_seq =="\x1b[B":
                        escape_seq =""
                        if self .history and self .history_index <len (self .history )-1 :
                            self .history_index +=1
                            next_cmd =self .history [self .history_index ]
                            self .channel .send ("\b \b"*len (cmd_buffer ))
                            cmd_buffer =next_cmd
                            self .channel .send (cmd_buffer )
                        elif self .history_index >=len (self .history )-1 :
                            self .channel .send ("\b \b"*len (cmd_buffer ))
                            cmd_buffer =""
                        continue
                    elif len (escape_seq )>=3 :
                        escape_seq =""
                        continue
                    continue

                if char =="\x1b":
                    escape_seq ="\x1b"
                    continue


                if char =="\t":
                    cmd_buffer =self ._handle_tab_completion (cmd_buffer )
                    continue


                if char in ("\r","\n"):
                    self .channel .send ("\r\n")
                    cmd =cmd_buffer .strip ()
                    cmd_buffer =""

                    if cmd :
                        self .history .append (cmd )
                        self .history_index =len (self .history )
                        print (f"[*] [Honeypot Shell] Attacker IP {self .client_ip } gõ: '{cmd }'")


                        self .log_event ({
                        "eventid":"cowrie.command.input",
                        "src_ip":self .client_ip ,
                        "session":self .session_id ,
                        "input":cmd ,
                        "timestamp":datetime .now (timezone .utc ).isoformat (),
                        })


                        output =self ._execute_command (cmd )
                        if output =="__EXIT__":
                            self .channel .close ()
                            return
                        if output :
                            self .channel .send (output )

                    self .channel .send (self .get_prompt ())


                elif char in ("\x08","\x7f"):
                    if cmd_buffer :
                        cmd_buffer =cmd_buffer [:-1 ]
                        self .channel .send ("\b \b")


                elif char =="\x03":
                    self .channel .send ("^C\r\n")
                    cmd_buffer =""
                    self .channel .send (self .get_prompt ())


                elif ord (char )>=32 :
                    cmd_buffer +=char
                    self .channel .send (char )

    def _handle_tab_completion (self ,cmd_buffer :str )->str :
        """Thực thi cơ chế Tab Autocomplete chuẩn Bash."""
        tokens =cmd_buffer .split ()
        if not cmd_buffer or cmd_buffer .endswith (" ")or len (tokens )==0 :

            entries =[name for name ,_ in self .vfs .list_dir (self .cwd )]
            if entries :
                self .channel .send ("\r\n"+"  ".join (entries )+"\r\n"+self .get_prompt ()+cmd_buffer )
            return cmd_buffer

        word =tokens [-1 ]
        matches =[]

        if len (tokens )==1 and not cmd_buffer .endswith (" "):

            matches =[c for c in self .KNOWN_COMMANDS if c .startswith (word )]

            for name ,info in self .vfs .list_dir (self .cwd ):
                if name .startswith (word ):
                    matches .append (name +("/"if info ["type"]=="dir"else ""))
        else :

            target_dir =self .cwd
            prefix =word
            if "/"in word :
                dir_part ,file_part =word .rsplit ("/",1 )
                target_dir =self .vfs .resolve_path (self .cwd ,dir_part )
                prefix =file_part

            for name ,info in self .vfs .list_dir (target_dir ):
                if name .startswith (prefix ):
                    suffix ="/"if info ["type"]=="dir"else " "
                    matches .append (name +suffix )

        if len (matches )==1 :
            match =matches [0 ]

            if "/"in word :
                missing =match [len (prefix ):]
            else :
                missing =match [len (word ):]
            cmd_buffer +=missing
            self .channel .send (missing )
        elif len (matches )>1 :

            self .channel .send ("\r\n"+"  ".join (matches )+"\r\n"+self .get_prompt ()+cmd_buffer )

        return cmd_buffer

    def _execute_command (self ,full_cmd :str )->str :
        """Xử lý lệnh với VFS thực tế."""

        if ">"in full_cmd :
            parts =full_cmd .split (">",1 )
            content =parts [0 ].strip ()
            if content .startswith ("echo "):
                content =content [5 :].strip ().strip ("\"'")+"\n"
            target_file =self .vfs .resolve_path (self .cwd ,parts [1 ].strip ())
            append =">>"in full_cmd
            self .vfs .write_file (target_file ,content ,append =append )
            return ""

        parts =full_cmd .split ()
        base =parts [0 ]if parts else ""
        args =parts [1 :]

        if base in ("exit","logout","quit"):
            return "__EXIT__"
        elif base =="clear":
            return "\033[H\033[2J"
        elif base in ("help","?"):
            return (
            "Ubuntu Linux Interactive Shell (Cowrie Honeynet Decoy)\r\n"
            "Supported commands: cd, pwd, ls, cat, touch, mkdir, rm, cp, mv, echo, chmod, ps, whoami, id, uname, ifconfig, history, curl, wget, clear, exit\r\n"
            )
        elif base =="pwd":
            return f"{self .cwd }\r\n"
        elif base =="cd":
            target =args [0 ]if args else "/root"
            resolved =self .vfs .resolve_path (self .cwd ,target )
            if self .vfs .is_dir (resolved ):
                self .cwd =resolved
                return ""
            elif self .vfs .is_file (resolved ):
                return f"bash: cd: {target }: Not a directory\r\n"
            else :
                return f"bash: cd: {target }: No such file or directory\r\n"
        elif base =="ls":
            return self ._handle_ls (args )
        elif base in ("cat","head","tail","more","less"):
            return self ._handle_cat (args )
        elif base =="mkdir":
            target =args [0 ]if args else ""
            if not target :
                return "mkdir: missing operand\r\n"
            resolved =self .vfs .resolve_path (self .cwd ,target )
            self .vfs .mkdir (resolved )
            return ""
        elif base =="touch":
            target =args [0 ]if args else ""
            if target :
                resolved =self .vfs .resolve_path (self .cwd ,target )
                self .vfs .write_file (resolved ,"")
            return ""
        elif base =="rm":
            target =args [-1 ]if args else ""
            if target and not target .startswith ("-"):
                resolved =self .vfs .resolve_path (self .cwd ,target )
                self .vfs .remove (resolved )
            return ""
        elif base =="whoami":
            return f"{self .username }\r\n"
        elif base =="id":
            return "uid=0(root) gid=0(root) groups=0(root)\r\n"
        elif base =="uname":
            return "Linux ubuntu-srv 5.15.0-89-generic #99-Ubuntu SMP Mon Oct 30 20:49:19 UTC 2023 x86_64 GNU/Linux\r\n"
        elif base =="hostname":
            return "ubuntu-srv\r\n"
        elif base in ("ifconfig","ip"):
            return (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n"
            "        inet 192.168.1.150  netmask 255.255.255.0  broadcast 192.168.1.255\r\n"
            "        inet6 fe80::a00:27ff:fe4e:66b1  prefixlen 64  scopeid 0x20<link>\r\n"
            "        ether 08:00:27:4e:66:b1  txqueuelen 1000  (Ethernet)\r\n"
            )
        elif base in ("netstat","ss"):
            return (
            "Active Internet connections (only servers)\r\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\r\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\r\n"
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\r\n"
            "tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\r\n"
            )
        elif base =="ps":
            return (
            "  PID TTY          TIME CMD\r\n"
            "    1 ?        00:00:01 systemd\r\n"
            "  412 ?        00:00:00 udevd\r\n"
            "  842 ?        00:00:00 sshd\r\n"
            "  912 pts/0    00:00:00 bash\r\n"
            "  980 pts/0    00:00:00 ps\r\n"
            )
        elif base =="history":
            out =""
            for idx ,h in enumerate (self .history ,1 ):
                out +=f"  {idx :4d}  {h }\r\n"
            return out
        elif base in ("wget","curl"):
            url =args [0 ]if args else "http://c2.bot/dropper.sh"

            mock_file =os .path .abspath ("./data/downloads/mirai_payload.sh")
            self .log_event ({
            "eventid":"cowrie.session.file_download",
            "src_ip":self .client_ip ,
            "session":self .session_id ,
            "url":url ,
            "outfile":mock_file ,
            "shasum":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "timestamp":datetime .now (timezone .utc ).isoformat (),
            })
            return f"Downloading {url } ... 100% [===================>] Done.\r\n"
        elif base =="ping":
            target_host =args [0 ]if args else "8.8.8.8"
            return (
            f"PING {target_host } ({target_host }) 56(84) bytes of data.\r\n"
            f"64 bytes from {target_host }: icmp_seq=1 ttl=116 time=14.2 ms\r\n"
            f"64 bytes from {target_host }: icmp_seq=2 ttl=116 time=14.5 ms\r\n"
            )
        elif base =="sudo":
            if args :
                return self ._execute_command (" ".join (args ))
            return "usage: sudo command\r\n"
        elif base =="chmod":
            return ""
        elif base in ("apt","apt-get"):
            return "Reading package lists... Done\r\nBuilding dependency tree... Done\r\nE: Could not get lock /var/lib/dpkg/lock-frontend (Permission denied)\r\n"
        elif base =="git":
            return "fatal: not a git repository (or any of the parent directories): .git\r\n"
        elif base in ("nano","vi","vim"):
            if not args :
                return ""
            target =args [0 ]
            resolved =self .vfs .resolve_path (self .cwd ,target )
            if not self .vfs .exists (resolved ):
                return f"[ New File: {target } ]\r\n"
            if self .vfs .is_dir (resolved ):
                return f"{base }: {target }: Is a directory\r\n"
            content =self .vfs .read_file (resolved )or ""
            return content .replace ("\n","\r\n")+"\r\n"
        elif base in ("which","whereis"):
            target_cmd =args [0 ]if args else "bash"
            return f"/usr/bin/{target_cmd }\r\n"
        else :
            return f"bash: {base }: command not found\r\n"

    def _handle_ls (self ,args :List [str ])->str :
        show_all =any ("-a"in a or "-la"in a or "-al"in a for a in args )
        long_format =any ("-l"in a for a in args )
        target_path =self .cwd
        for a in args :
            if not a .startswith ("-"):
                target_path =self .vfs .resolve_path (self .cwd ,a )
                break

        if not self .vfs .exists (target_path ):
            return f"ls: cannot access '{target_path }': No such file or directory\r\n"

        if self .vfs .is_file (target_path ):
            return f"{os .path .basename (target_path )}\r\n"

        entries =self .vfs .list_dir (target_path )
        if not show_all :
            entries =[(name ,info )for name ,info in entries if not name .startswith (".")]

        if long_format :
            output =f"total {len (entries )*4 }\r\n"
            for name ,info in entries :
                perm =info .get ("perm","-rw-r--r--")
                owner =info .get ("owner","root")
                group =info .get ("group","root")
                size =len (info .get ("content",""))if info ["type"]=="file"else 4096
                output +=f"{perm } 1 {owner :8s} {group :8s} {size :6d} Oct  2 10:00 {name }\r\n"
            return output
        else :
            names =[name for name ,_ in entries ]
            return "  ".join (names )+("\r\n"if names else "")

    def _handle_cat (self ,args :List [str ])->str :
        if not args :
            return ""
        target =args [0 ]
        resolved =self .vfs .resolve_path (self .cwd ,target )
        if not self .vfs .exists (resolved ):
            return f"cat: {target }: No such file or directory\r\n"
        if self .vfs .is_dir (resolved ):
            return f"cat: {target }: Is a directory\r\n"

        content =self .vfs .read_file (resolved )
        return (content or "").replace ("\n","\r\n")


class MiniSSHHoneypot :
    def __init__ (self ,host :str ="0.0.0.0",port :int =2222 ,log_file :str ="./data/cowrie.json",soar_enforcer =None ,event_callback =None ):
        self .host =host
        self .port =port
        self .log_file =log_file
        self .soar_enforcer =soar_enforcer
        self .event_callback =event_callback
        self .is_running =False
        self .server_socket :Optional [socket .socket ]=None
        self ._thread :Optional [threading .Thread ]=None

        self .host_key =self ._get_or_create_host_key ()

    def _get_or_create_host_key (self ):
        """Ưu tiên host key ECDSA.

        Paramiko >= 5 và OpenSSH >= 8.8 đã loại bỏ thuật toán chữ ký `ssh-rsa`
        (SHA-1), nên host key RSA 2048 khiến client hiện đại từ chối bắt tay
        (client báo 'Error reading SSH protocol banner'). Dùng ECDSA để honeypot
        nhận được kết nối SSH thật từ các client/tool tấn công hiện nay.
        """
        key_path ="./data/honeypot_ecdsa.key"
        os .makedirs (os .path .dirname (os .path .abspath (key_path )),exist_ok =True )
        if os .path .exists (key_path ):
            try :
                return paramiko .ECDSAKey (filename =key_path )
            except Exception :
                pass
        try :
            key =paramiko .ECDSAKey .generate (bits =256 )
            key .write_private_key_file (key_path )
            return key
        except Exception :

            rsa_path ="./data/honeypot_rsa.key"
            if os .path .exists (rsa_path ):
                try :
                    return paramiko .RSAKey (filename =rsa_path )
                except Exception :
                    pass
            key =paramiko .RSAKey .generate (2048 )
            key .write_private_key_file (rsa_path )
            return key

    def is_ip_blocked (self ,ip :str )->bool :
        if self .soar_enforcer and hasattr (self .soar_enforcer ,"blocked_ips"):
            return ip in self .soar_enforcer .blocked_ips
        return False

    def log_event (self ,event :dict ):
        """Ghi sự kiện vào file cowrie.json chuẩn format và gọi callback lập tức."""
        try :
            os .makedirs (os .path .dirname (os .path .abspath (self .log_file )),exist_ok =True )
            with open (self .log_file ,"a",encoding ="utf-8")as f :
                f .write (json .dumps (event )+"\n")
                f .flush ()
        except Exception as e :
            print (f"[-] Lỗi ghi log honeypot: {e }")

        if self .event_callback :
            try :
                self .event_callback (event )
            except Exception as e :
                print (f"[-] Lỗi callback event: {e }")

    def _peek_ssh_banner (self ,client_socket ,ip :str ,port :int )->bool :
        """
        Đọc trước (non-destructive) dữ liệu client gửi để xác định có phải SSH không.

        Lý do: khi honeypot bị phơi ra Internet, scanner/botnet gửi trực tiếp
        HTTP GET, TLS ClientHello hoặc byte rác. paramiko.Transport sẽ cố decode
        chúng như UTF-8 và ném UnicodeDecodeError kèm traceback đầy màn hình,
        che mất log tấn công thật. Hàm này chặn từ đầu và ghi nhận thành
        sự kiện có cấu trúc thay vì traceback.

        Dùng MSG_PEEK nên dữ liệu KHÔNG bị tiêu thụ — paramiko vẫn đọc được sau.
        """
        try :


            client_socket .settimeout (2.0 )
            head =client_socket .recv (64 ,socket .MSG_PEEK )
        except socket .timeout :


            return True
        except OSError :
            return False
        finally :
            try :
                client_socket .settimeout (None )
            except OSError :
                pass

        if not head :
            return False

        if head .startswith (b"SSH-"):
            return True


        if head .startswith ((b"GET ",b"POST ",b"HEAD ",b"OPTIONS ")):
            kind ,mitre ="HTTP request tới cổng SSH","T1595.002 - Active Scanning: Vulnerability Scanning"
        elif head .startswith (b"\x16\x03"):
            kind ,mitre ="TLS ClientHello tới cổng SSH","T1595.002 - Active Scanning"
        else :
            kind ,mitre ="Byte rác không phải giao thức SSH","T1595 - Active Scanning"

        printable ="".join (chr (b )if 32 <=b <127 else "."for b in head [:32 ])
        print (f"[!] [NON-SSH TRAFFIC] IP {ip }:{port } | {kind } | raw='{printable }'")

        try :
            self .log_event ({
            "eventid":"cowrie.client.non_ssh_traffic",
            "src_ip":ip ,
            "src_port":port ,
            "detected_as":kind ,
            "mitre_technique":mitre ,
            "raw_hex":head [:32 ].hex (),
            "raw_ascii":printable ,
            "timestamp":datetime .now (timezone .utc ).isoformat (),
            })
        except Exception :
            pass

        return False

    def handle_client (self ,client_socket ,addr ):
        ip ,port =addr
        print (f"\n[KẾT NỐI MỚI] Kẻ tấn công từ IP {ip }:{port } vừa kết nối SSH vào Honeypot!")
        if self .is_ip_blocked (ip ):
            print (f"[!] [SOAR Active Defense] Phát hiện kết nối từ IP bị chặn Firewall: {ip }. Đóng kết nối lập tức!")
            client_socket .close ()
            return


        if self .soar_enforcer and hasattr (self .soar_enforcer ,"is_tarpitted")and self .soar_enforcer .is_tarpitted (ip ):
            print (f"\n[SOAR TARPIT KÍCH HOẠT] IP {ip } đang bị giam lỏng trong hố Tarpit! Gửi dữ liệu chậm cực độ để làm treo đối phương...")
            banner =b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"
            try :
                for byte in banner :
                    client_socket .send (bytes ([byte ]))
                    time .sleep (3 )
                while True :
                    client_socket .send (b"\r\n")
                    time .sleep (5 )
            except Exception :
                pass
            finally :
                client_socket .close ()
            return

        transport =None
        try :


            if not self ._peek_ssh_banner (client_socket ,ip ,port ):
                return

            transport =paramiko .Transport (client_socket )
            transport .add_server_key (self .host_key )
            server =HoneypotSSHServer (ip ,self .log_event ,self .is_ip_blocked )

            try :
                transport .start_server (server =server )
            except paramiko .SSHException :
                return

            channel =transport .accept (20 )
            if channel is None :
                return

            server .event .wait (10 )
            if not server .event .is_set ():
                channel .close ()
                return


            target_host_ip =None
            try :
                sock_ip =client_socket .getsockname ()[0 ]
                if sock_ip and sock_ip not in ("0.0.0.0","127.0.0.1"):
                    target_host_ip =sock_ip
            except Exception :
                pass

            session =CowrieSessionHandler (
            channel =channel ,
            client_ip =ip ,
            session_id =server .session_id ,
            username =server .authenticated_user ,
            log_event_func =self .log_event ,
            host_ip =target_host_ip ,
            )
            session .run ()

        except Exception as e :
            pass
        finally :
            if transport :
                transport .close ()
            client_socket .close ()

    def start (self ):
        self .is_running =True
        self .server_socket =socket .socket (socket .AF_INET ,socket .SOCK_STREAM )
        self .server_socket .setsockopt (socket .SOL_SOCKET ,socket .SO_REUSEADDR ,1 )
        self .server_socket .bind ((self .host ,self .port ))
        self .server_socket .listen (50 )
        self .server_socket .settimeout (1.0 )

        print (f"[SSH HONEYPOT] Đang lắng nghe kết nối SSH THẬT tại port {self .port } (0.0.0.0:{self .port })")
        print (f"    [+] Thử nghiệm kết nối thật: ssh root@127.0.0.1 -p {self .port }\n")

        while self .is_running :
            try :
                client_sock ,addr =self .server_socket .accept ()
                t =threading .Thread (target =self .handle_client ,args =(client_sock ,addr ),daemon =True )
                t .start ()
            except socket .timeout :
                continue
            except Exception :
                break

    def start_background (self ):
        self ._thread =threading .Thread (target =self .start ,daemon =True )
        self ._thread .start ()

    def stop (self ):
        self .is_running =False
        if self .server_socket :
            try :
                self .server_socket .close ()
            except Exception :
                pass
