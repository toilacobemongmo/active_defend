"""Kiem tra deployment honeypot tren VPS (Oracle Cloud / VPS bat ky) tu may local.

Chay:
    python scripts/verify_remote_deploy.py --host 140.238.x.x
    python scripts/verify_remote_deploy.py --host 140.238.x.x --port 2222 --canary-port 8080

Script tra loi 4 cau hoi theo dung thu tu debug:
    1. Port co mo khong?              -> Security List + firewall OS
    2. SSH banner co dung khong?      -> container co chay, paramiko co len
    3. Canary webhook co song khong?  -> port 8080 mapping
    4. Brute-force co ban alert khong -> correlation engine + SOAR

Khong can thu vien ngoai (chi socket + urllib).
"""

from __future__ import annotations

import argparse
import socket
import sys
import time
import urllib .error
import urllib .request

try :
    sys .stdout .reconfigure (encoding ="utf-8",errors ="replace")
except Exception :
    pass

GREEN ="\033[92m"
RED ="\033[91m"
YELLOW ="\033[93m"
CYAN ="\033[96m"
RESET ="\033[0m"


def ok (msg :str )->None :
    print (f"{GREEN }[ OK ]{RESET } {msg }")


def fail (msg :str )->None :
    print (f"{RED }[FAIL]{RESET } {msg }")


def warn (msg :str )->None :
    print (f"{YELLOW }[WARN]{RESET } {msg }")


def head (msg :str )->None :
    print (f"\n{CYAN }== {msg } =={RESET }")


def check_port (host :str ,port :int ,timeout :float =8.0 )->bool :
    """Mo TCP toi host:port. Day la test phan biet duoc 'bi chan' vs 'khong listen'."""
    try :
        with socket .create_connection ((host ,port ),timeout =timeout ):
            return True
    except socket .timeout :
        fail (f"{host }:{port } -> TIMEOUT (goi y: Security List chua mo port nay)")
        return False
    except ConnectionRefusedError :
        fail (f"{host }:{port } -> REFUSED (goi y: VM song nhung khong co process listen)")
        return False
    except OSError as exc :
        fail (f"{host }:{port } -> {type (exc ).__name__ }: {exc }")
        return False


def read_ssh_banner (host :str ,port :int ,timeout :float =10.0 )->str :
    try :
        sock =socket .create_connection ((host ,port ),timeout =timeout )
    except OSError as exc :
        return f"ERROR:{type (exc ).__name__ }"
    try :
        return sock .recv (256 ).decode (errors ="replace").strip ()
    finally :
        sock .close ()


def check_canary (host :str ,port :int ,timeout :float =10.0 )->bool :
    """Canary webhook tra 200 cho bat ky path nao (ke ca /)."""
    url =f"http://{host }:{port }/"
    try :
        with urllib .request .urlopen (url ,timeout =timeout )as resp :
            ok (f"Canary {url } -> HTTP {resp .status }")
            return True
    except urllib .error .HTTPError as exc :

        warn (f"Canary {url } -> HTTP {exc .code } (server song, endpoint khac)")
        return True
    except Exception as exc :
        fail (f"Canary {url } -> {type (exc ).__name__ }: {exc }")
        return False


def paramiko_bruteforce (host :str ,port :int ,username :str ,attempts :int )->str :
    """Thu dang nhap sai nhieu lan de kich hoat T1110.001. Tra ve tom tat."""
    try :
        import paramiko
    except ImportError :
        return "SKIP (chua cai paramiko: pip install paramiko)"

    results =[]
    for i in range (1 ,attempts +1 ):
        client =paramiko .SSHClient ()
        client .set_missing_host_key_policy (paramiko .AutoAddPolicy ())
        try :
            client .connect (
            host ,
            port =port ,
            username =username ,
            password =f"wrongpass{i }",
            timeout =12 ,
            banner_timeout =15 ,
            auth_timeout =15 ,
            allow_agent =False ,
            look_for_keys =False ,
            )
            results .append ("SUCCESS(!)")
        except paramiko .AuthenticationException :
            results .append ("AUTH_FAILED")
        except Exception as exc :
            results .append (f"ERROR:{type (exc ).__name__ }")
        finally :
            client .close ()
        time .sleep (0.4 )
    return ", ".join (results )


def main ()->None :
    parser =argparse .ArgumentParser (
    description ="Verify honeypot deployment tren VPS tu may local"
    )
    parser .add_argument ("--host",required =True ,help ="IP public cua VPS")
    parser .add_argument ("--port",type =int ,default =2222 ,help ="Port SSH honeypot")
    parser .add_argument ("--canary-port",type =int ,default =8080 ,help ="Port canary webhook")
    parser .add_argument ("--username",default ="admin",help ="Username gia de brute-force")
    parser .add_argument ("--attempts",type =int ,default =6 ,help ="So lan dang nhap sai")
    parser .add_argument ("--skip-canary",action ="store_true",help ="Bo qua test canary")
    parser .add_argument ("--skip-bruteforce",action ="store_true",help ="Bo qua test brute-force")
    args =parser .parse_args ()

    host =args .host
    print (f"{CYAN }Kiem tra deployment honeypot tai {host }{RESET }")

    all_ok =True


    head (f"1. Kiem tra port {args .port } co mo tu Internet")
    if check_port (host ,args .port ):
        ok (f"{host }:{args .port } -> CONNECTED")
    else :
        all_ok =False
        print (
        f"\n{YELLOW }Chan doan thu tu:{RESET }\n"
        "  a) OCI: Networking -> VCN -> Security Lists -> Default Security List\n"
        "     -> Add Ingress Rule: source 0.0.0.0/0, TCP, dest port "
        f"{args .port }\n"
        f"  b) Tren VM: sudo iptables -I INPUT -p tcp --dport {args .port } -j ACCEPT\n"
        f"     (hoac: sudo firewall-cmd --permanent --add-port={args .port }/tcp && sudo firewall-cmd --reload)\n"
        f"  c) Tren VM: sudo ss -lntp | grep {args .port }  # phai thay docker-proxy listen\n"
        "  d) Tren VM: docker compose ps  # container phai Up (healthy)"
        )


    if all_ok :
        head ("2. Doc SSH banner (xac nhan paramiko honeypot dang chay)")
        banner =read_ssh_banner (host ,args .port )
        if banner .startswith ("SSH-"):
            ok (f"Banner: {banner }")
            if "paramiko"in banner :
                ok ("Dung la paramiko honeypot, khong phai OpenSSH that")
            else :
                warn ("Banner khong phai paramiko -> co the dang noi nham vao SSH that!")
        else :
            fail (f"Banner khong hop le: {banner !r }")
            all_ok =False


    if all_ok and not args .skip_canary :
        head (f"3. Canary webhook port {args .canary_port }")
        if not check_canary (host ,args .canary_port ):
            all_ok =False
            print (
            f"{YELLOW }Goi y:{RESET } canary_server bind 0.0.0.0:{args .canary_port }?\n"
            "  docker-compose.yml phai co: - \"8080:8080\"\n"
            f"  OCI Security List phai mo TCP {args .canary_port }"
            )


    if all_ok and not args .skip_bruteforce :
        head (f"4. Gui {args .attempts } lan dang nhap sai (kich hoat T1110.001)")
        summary =paramiko_bruteforce (host ,args .port ,args .username ,args .attempts )
        print (f"     Ket qua: {summary }")
        if "AUTH_FAILED"in summary :
            ok ("Honeypot tu choi dung cach")
        print (
        f"\n{YELLOW }Buoc cuoi — chay TREN VM de verify IP that:{RESET }\n"
        "  docker compose exec soc-core tail -3 data/cowrie.json\n"
        f"  -> phai thay \"src_ip\": \"<IP that cua ban>\", KHONG phai 127.0.0.1"
        )


    print ()
    if all_ok :
        ok (f"DEPLOYMENT OK — honeypot dang chay that tai {host }:{args .port }")
        sys .exit (0 )
    else :
        fail ("DEPLOYMENT CHUA HOAN CHINH — xem chan doan phia tren")
        sys .exit (1 )


if __name__ =="__main__":
    main ()
