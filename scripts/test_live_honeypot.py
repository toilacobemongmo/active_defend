"""Kiểm thử Live SSH Honeypot bằng kết nối SSH thật (demo kịch bản brute-force).

Chạy:
    python scripts/test_live_honeypot.py --host 127.0.0.1 --port 2222 --attempts 6
    python scripts/test_live_honeypot.py --host 127.0.0.1 --port 2222 --success
"""

import argparse
import socket
import sys
import time

try :
    import paramiko
except ImportError :
    print ("[-] Thieu paramiko: pip install paramiko")
    sys .exit (1 )

try :
    sys .stdout .reconfigure (encoding ="utf-8",errors ="replace")
except Exception :
    pass


def read_banner (host :str ,port :int )->str :
    s =socket .create_connection ((host ,port ),timeout =8 )
    try :
        return s .recv (128 ).decode (errors ="replace").strip ()
    finally :
        s .close ()


def attempt (host :str ,port :int ,username :str ,password :str )->str :
    client =paramiko .SSHClient ()
    client .set_missing_host_key_policy (paramiko .AutoAddPolicy ())
    try :
        client .connect (
        host ,
        port =port ,
        username =username ,
        password =password ,
        timeout =10 ,
        banner_timeout =15 ,
        auth_timeout =15 ,
        allow_agent =False ,
        look_for_keys =False ,
        )
        return "SUCCESS"
    except paramiko .AuthenticationException :
        return "AUTH_FAILED"
    except Exception as exc :
        return f"ERROR:{type (exc ).__name__ }:{exc }"
    finally :
        client .close ()


VALID_ACCOUNTS ={
"root":"monkey",
"ubuntu":"1234567",
}


def main ()->None :
    parser =argparse .ArgumentParser (description ="Test Live SSH Honeypot")
    parser .add_argument ("--host",default ="127.0.0.1")
    parser .add_argument ("--port",type =int ,default =2222 )
    parser .add_argument ("--username",default ="root")
    parser .add_argument ("--attempts",type =int ,default =6 )
    parser .add_argument ("--success",action ="store_true",
    help ="Dùng mật khẩu đúng lấy từ VALID_ACCOUNTS (root:monkey, ubuntu:1234567)")
    args =parser .parse_args ()

    print (f"[*] Banner: {read_banner (args .host ,args .port )}")

    if args .success :
        pwd =VALID_ACCOUNTS .get (args .username )
        if pwd is None :
            print (f"[-] Không biết mật khẩu đúng cho user '{args .username }'. "
            f"Hỗ trợ: {', '.join (VALID_ACCOUNTS )}")
            return
        result =attempt (args .host ,args .port ,args .username ,pwd )
        print (f"[*] Login {args .username }/{pwd } -> {result }")
        return

    for i in range (1 ,args .attempts +1 ):
        pwd =f"wrongpass{i }"
        result =attempt (args .host ,args .port ,args .username ,pwd )
        print (f"[*] Lan {i }: user={args .username } pass={pwd } -> {result }")
        time .sleep (0.3 )


if __name__ =="__main__":
    main ()
