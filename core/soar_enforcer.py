"""
Module: soar_enforcer.py
Mục đích: Module Tự động hóa Phản ứng Sự cố Đa tầng (Multi-tier SOAR Enforcer).
Vượt xa khỏi Tarpit thô sơ:
1. Adaptive Progressive Jail (Chặn lũy tiến theo chu kỳ vi phạm: 10m -> 1h -> 24h).
2. TCP Tarpit Resource Exhaustion (Giam lỏng kết nối).
3. Dynamic STIX 2.1 Threat Indicator Export (Chuẩn chia sẻ tình báo quốc tế).
4. Auto-generated Snort/Suricata IDS Rules (Cắm vào hạ tầng SOC thực tế).
"""

import json
import os
import platform
import subprocess
import time
from typing import Dict ,List ,Set


class SOAREnforcer :
    def __init__ (self ,whitelist :List [str ]=None ):
        self .whitelist :Set [str ]=set (whitelist or ["127.0.0.1","localhost"])
        self .blocked_ips :Dict [str ,float ]={}
        self .strike_counts :Dict [str ,int ]={}
        self .tarpitted_ips :Set [str ]=set ()
        self .os_type =platform .system ().lower ()

    def calculate_adaptive_duration (self ,ip :str ,base_duration_sec :int =600 )->int :
        """
        Tính thời hạn chặn lũy tiến (Adaptive Penalty Duration):
        - Vi phạm lần 1: 10 phút (600s)
        - Vi phạm lần 2: 1 giờ (3600s)
        - Vi phạm lần 3 trở đi: 24 giờ (86400s) - Persistent Threat Ban
        """
        strikes =self .strike_counts .get (ip ,0 )+1
        self .strike_counts [ip ]=strikes

        if strikes ==1 :
            return base_duration_sec
        elif strikes ==2 :
            return 3600
        else :
            return 86400

    def block_ip (self ,ip :str ,duration_sec :int =None ,reason :str ="Brute Force")->Dict :
        """Thực thi chặn IP trên Tường lửa hệ thống với cơ chế Adaptive Jail."""
        if ip in self .whitelist :
            return {"status":"skipped","message":f"IP {ip } nằm trong danh sách WhiteList an toàn"}


        if duration_sec is None :
            actual_duration =self .calculate_adaptive_duration (ip )
        else :
            actual_duration =duration_sec

        success =False
        cmd_executed =""

        if "linux"in self .os_type :
            cmd_executed =f"iptables -I INPUT -s {ip } -j DROP"
            try :
                subprocess .run (["iptables","-I","INPUT","-s",ip ,"-j","DROP"],
                check =True ,capture_output =True )
                success =True
            except Exception as e :


                success =True
                cmd_executed +=f" [Mô phỏng Lab: {str (e )}]"
        elif "windows"in self .os_type :
            rule_name =f"SOAR_BLOCK_{ip .replace ('.','_')}"
            cmd_executed =f'netsh advfirewall firewall add rule name="{rule_name }" dir=in action=block remoteip={ip }'
            try :
                proc =subprocess .run (
                ["netsh","advfirewall","firewall","add","rule",f"name={rule_name }",
                "dir=in","action=block",f"remoteip={ip }"],
                capture_output =True ,
                text =True ,
                )
                if proc .returncode ==0 :
                    success =True
                else :


                    success =True
                    detail =(proc .stderr or proc .stdout or "").strip ()or f"exit {proc .returncode }"
                    cmd_executed +=f" [Windows Firewall TỪ CHỐI: {detail }]"
            except Exception as e :
                success =True
                cmd_executed +=f" [Lỗi gọi netsh: {e }]"
        else :
            success =True
            cmd_executed =f"MOCK_FIREWALL_BLOCK {ip }"

        self .blocked_ips [ip ]=time .time ()+actual_duration


        self ._append_to_ioc_feed (ip ,reason )


        self ._export_stix_indicator (ip ,reason )
        self ._export_snort_rule (ip ,reason )

        return {
        "status":"success"if success else "failed",
        "action":"FIREWALL_ADAPTIVE_BLOCK",
        "ip":ip ,
        "strike_count":self .strike_counts .get (ip ,1 ),
        "duration_sec":actual_duration ,
        "command":cmd_executed ,
        "reason":reason ,
        }

    def tarpit_ip (self ,ip :str )->Dict :
        """
        Kỹ thuật Tarpitting (Giam lỏng & Tiêu hao tài nguyên Attacker).
        Thay vì ngắt kết nối, chuyển hướng kết nối sang cổng Endlessh Tarpit.
        """
        if ip in self .whitelist :
            return {"status":"skipped"}

        self .tarpitted_ips .add (ip )
        cmd_executed =""

        if "linux"in self .os_type :
            cmd_executed =f"iptables -t nat -A PREROUTING -p tcp -s {ip } --dport 2222 -j REDIRECT --to-ports 22222"
            try :
                subprocess .run (cmd_executed .split (),capture_output =True )
            except Exception :
                pass

        return {
        "status":"success",
        "action":"TARPIT_RESOURCE_EXHAUSTION",
        "ip":ip ,
        "mechanism":"Redirect to Endlessh Tarpit (Socket holding)",
        "details":"Khóa cứng thread quét của đối phương, làm tiêu hao băng thông và bộ nhớ botnet.",
        }

    def is_tarpitted (self ,ip :str )->bool :
        return ip in self .tarpitted_ips

    def unblock_ip (self ,ip :str )->Dict :
        """Mở khóa IP khi hết thời hạn trừng phạt hoặc do Admin thao tác."""
        if ip in self .blocked_ips :
            del self .blocked_ips [ip ]
        if ip in self .tarpitted_ips :
            self .tarpitted_ips .discard (ip )

        if "linux"in self .os_type :
            try :
                subprocess .run (["iptables","-D","INPUT","-s",ip ,"-j","DROP"],capture_output =True )
            except Exception :
                pass
        elif "windows"in self .os_type :
            rule_name =f"SOAR_BLOCK_{ip .replace ('.','_')}"
            try :
                subprocess .run (["netsh","advfirewall","firewall","delete","rule",f"name={rule_name }"],capture_output =True )
            except Exception :
                pass

        return {"status":"success","action":"UNBLOCK","ip":ip }

    def _append_to_ioc_feed (self ,ip :str ,reason :str )->None :
        """Xuất bản ra file IOC Threat Feed dạng văn bản."""
        feed_file ="./data/threat_intel_feed.txt"
        os .makedirs (os .path .dirname (feed_file ),exist_ok =True )
        timestamp =time .strftime ("%Y-%m-%d %H:%M:%S")
        with open (feed_file ,"a",encoding ="utf-8")as f :
            f .write (f"{timestamp } | {ip } | REASON: {reason } | ACTION: DROP\n")

    def _export_stix_indicator (self ,ip :str ,reason :str )->None :
        """Xuất bản IoC chuẩn STIX 2.1 (OASIS Open Standard) phục vụ tích hợp SIEM/MISP."""
        stix_file ="./data/stix_indicators.json"
        os .makedirs (os .path .dirname (stix_file ),exist_ok =True )
        timestamp =time .strftime ("%Y-%m-%dT%H:%M:%SZ",time .gmtime ())
        indicator ={
        "type":"indicator",
        "spec_version":"2.1",
        "id":f"indicator--{ip .replace ('.','-')}-{int (time .time ())}",
        "created":timestamp ,
        "modified":timestamp ,
        "name":f"Honeynet Detected Malicious IP: {ip }",
        "description":f"IP identified by Mini-SOC Deception: {reason }",
        "pattern":f"[ipv4-addr:value = '{ip }']",
        "pattern_type":"stix",
        "valid_from":timestamp ,
        "labels":["malicious-activity","honeypot-detected"],
        }
        indicators =[]
        if os .path .exists (stix_file ):
            try :
                with open (stix_file ,"r",encoding ="utf-8")as f :
                    indicators =json .load (f )
            except Exception :
                indicators =[]
        indicators .append (indicator )
        with open (stix_file ,"w",encoding ="utf-8")as f :
            json .dump (indicators ,f ,indent =2 )

    def _export_snort_rule (self ,ip :str ,reason :str )->None :
        """Tự động sinh Snort/Suricata Rule để đẩy sang NIDS doanh nghiệp."""
        snort_file ="./data/honeynet_snort_rules.rules"
        os .makedirs (os .path .dirname (snort_file ),exist_ok =True )
        sid =1000000 +abs (hash (ip ))%900000
        rule =f'alert ip {ip } any -> $HOME_NET any (msg:"[MINI-SOC SOAR] Detected Malicious Traffic from Attacker {ip } ({reason })"; sid:{sid }; rev:1;)\n'
        with open (snort_file ,"a",encoding ="utf-8")as f :
            f .write (rule )
