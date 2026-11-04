
"""
Mo tunnel TCP cong khai (serveo.net) tro ve honeypot dang chay tren may local,
sau do tu dong test ket noi SSH tu ben ngoai de chung minh honeypot da "len mang".

Cach dung:
    python scripts/expose_tunnel.py --local-port 2222
    python scripts/expose_tunnel.py --local-port 2222 --tries 10
"""
import argparse
import os
import re
import subprocess
import sys
import time

sys .stdout .reconfigure (encoding ="utf-8",errors ="replace")

SSH =r"C:\Windows\System32\OpenSSH\ssh.exe"
OUT =".sv.out"
ERR =".sv.err"


def kill_old_tunnels ()->None :
    subprocess .run (["taskkill","/F","/IM","ssh.exe"],
    capture_output =True ,text =True )
    time .sleep (2 )


def start_tunnel (local_port :int )->subprocess .Popen :
    for f in (OUT ,ERR ):
        if os .path .exists (f ):
            os .remove (f )


    args =[
    SSH ,"-T",
    "-o","StrictHostKeyChecking=no",
    "-o","UserKnownHostsFile=/dev/null",
    "-o","ServerAliveInterval=20",
    "-o","ExitOnForwardFailure=yes",
    "-R",f"0:127.0.0.1:{local_port }",
    "serveo.net",
    ]
    return subprocess .Popen (args ,stdout =open (OUT ,"w",encoding ="utf-8",errors ="replace"),
    stderr =open (ERR ,"w",encoding ="utf-8",errors ="replace"),
    stdin =subprocess .DEVNULL )


def wait_for_endpoint (timeout_sec :int =40 ):
    pattern =re .compile (r"serveousercontent\.com:(\d+)")
    deadline =time .time ()+timeout_sec
    while time .time ()<deadline :
        for f in (OUT ,ERR ):
            if os .path .exists (f ):
                try :
                    text =open (f ,encoding ="utf-8",errors ="replace").read ()
                except OSError :
                    continue
                m =pattern .search (text )
                if m :
                    return "serveousercontent.com",int (m .group (1 ))
        time .sleep (1 )
    return None ,None


def main ()->int :
    ap =argparse .ArgumentParser ()
    ap .add_argument ("--local-port",type =int ,default =2222 )
    ap .add_argument ("--tries",type =int ,default =6 ,help ="So lan thu lai neu serveo tu choi")
    args =ap .parse_args ()

    for attempt in range (1 ,args .tries +1 ):
        print (f"[*] Lan thu {attempt }/{args .tries }: mo tunnel -> 127.0.0.1:{args .local_port }")
        kill_old_tunnels ()
        proc =start_tunnel (args .local_port )
        host ,port =wait_for_endpoint (40 )
        if host :
            print (f"[+] DA CO ENDPOINT CONG KHAI: {host }:{port }")
            print (f"[i] SSH tu ben ngoai:  ssh -p {port } root@{host }")
            print (f"[i] Tunnel PID={proc .pid } (dung taskkill /F /IM ssh.exe de dong)")
            return 0
        err =""
        if os .path .exists (ERR ):
            err =open (ERR ,encoding ="utf-8",errors ="replace").read ().strip ()
        print (f"[-] That bai. stderr: {err .splitlines ()[-1 ]if err else '(rong)'}")
        proc .kill ()
        time .sleep (10 )

    print ("[-] Khong lay duoc endpoint cong khai. Thu lai sau hoac dung ngrok/pinggy.")
    return 1


if __name__ =="__main__":
    sys .exit (main ())
