"""
Module: reverse_intel.py
Mục đích: Module Trinh sát ngược Kẻ tấn công (Reverse Reconnaissance & Threat Intelligence Engine).
Tự động thu thập thông tin tình báo đối phương (OSINT, AbuseIPDB, Shodan, Reverse Port Scanning, Fingerprinting).
"""

import socket
import json
import requests
from typing import Dict ,List ,Optional


class ReverseIntelligenceEngine :
    def __init__ (self ,abuseipdb_key :Optional [str ]=None ,shodan_key :Optional [str ]=None ):
        self .abuseipdb_key =abuseipdb_key
        self .shodan_key =shodan_key

    def gather_full_recon (self ,ip :str )->Dict :
        """Thực hiện trinh sát toàn diện đối với IP của kẻ tấn công."""

        geo_info =self .lookup_geoip (ip )


        abuse_info =self .lookup_abuseipdb (ip )


        open_ports =self .safe_reverse_port_scan (ip )


        shodan_info =self .lookup_shodan (ip )if self .shodan_key else {"status":"no_key"}

        return {
        "target_ip":ip ,
        "geo_intel":geo_info ,
        "reputation":abuse_info ,
        "active_services":open_ports ,
        "shodan_intel":shodan_info ,
        "threat_classification":self ._classify_threat (abuse_info ,open_ports ),
        }

    def lookup_geoip (self ,ip :str )->Dict :
        """Tra cứu tọa độ địa lý, quốc gia, ISP của IP tấn công."""
        if ip in ("127.0.0.1","localhost","0.0.0.0")or ip .startswith ("192.168.")or ip .startswith ("10."):
            return {
            "country":"Local / Private Lab Network",
            "city":"Private Subnet",
            "isp":"Internal Gateway",
            "org":"Honeynet Lab",
            "countryCode":"LOC",
            }
        try :
            url =f"http://ip-api.com/json/{ip }?fields=status,country,countryCode,regionName,city,isp,org,as,query"
            resp =requests .get (url ,timeout =4 )
            if resp .status_code ==200 :
                data =resp .json ()
                if data .get ("status")=="success":
                    return data
        except Exception as e :
            return {"error":f"GeoIP query failed: {str (e )}"}

        return {"country":"Unknown","city":"Unknown","isp":"Unknown"}

    def lookup_abuseipdb (self ,ip :str )->Dict :
        """Kiểm tra chỉ số danh tiếng độc hại trên cơ sở dữ liệu AbuseIPDB toàn cầu."""
        if not self .abuseipdb_key or self .abuseipdb_key =="YOUR_ABUSEIPDB_API_KEY":

            return {
            "abuseConfidenceScore":85 ,
            "totalReports":142 ,
            "isWhitelisted":False ,
            "usageType":"Data Center/Web Hosting/Transit",
            "source":"Mock/Simulated Academic Intelligence",
            }

        headers ={
        "Key":self .abuseipdb_key ,
        "Accept":"application/json",
        }
        params ={"ipAddress":ip ,"maxAgeInDays":90 }
        try :
            resp =requests .get (
            "https://api.abuseipdb.com/api/v2/check",
            headers =headers ,
            params =params ,
            timeout =5 ,
            )
            if resp .status_code ==200 :
                return resp .json ().get ("data",{})
        except Exception as e :
            return {"error":str (e )}

        return {"abuseConfidenceScore":0 ,"totalReports":0 }

    def lookup_shodan (self ,ip :str )->Dict :
        """Truy vấn các dịch vụ Shodan đã lập chỉ mục về IP mục tiêu."""
        if not self .shodan_key or self .shodan_key =="YOUR_SHODAN_API_KEY":
            return {"status":"skipped","message":"No valid Shodan API key"}

        try :
            url =f"https://api.shodan.io/shodan/host/{ip }?key={self .shodan_key }"
            resp =requests .get (url ,timeout =5 )
            if resp .status_code ==200 :
                data =resp .json ()
                return {
                "ports":data .get ("ports",[]),
                "vulns":list (data .get ("vulns",{}).keys ()),
                "hostnames":data .get ("hostnames",[]),
                "os":data .get ("os","Unknown"),
                }
        except Exception as e :
            return {"error":str (e )}

        return {}

    def safe_reverse_port_scan (self ,ip :str ,ports :Optional [List [int ]]=None )->List [int ]:
        """
        Quét cổng an toàn (Safe Banner / Port Probing).
        Chỉ kiểm tra các cổng dịch vụ công cộng phổ biến với timeout ngắn (300ms) để xác định
        máy tấn công là Router bị hack (port 80/23), Proxy/Tor (port 8080/9050), hay Máy cá nhân (C2).
        """
        if ports is None :

            ports =[21 ,22 ,23 ,80 ,443 ,1080 ,3128 ,3389 ,8080 ,8888 ]

        open_ports =[]
        for port in ports :
            s =socket .socket (socket .AF_INET ,socket .SOCK_STREAM )
            s .settimeout (0.3 )
            try :
                result =s .connect_ex ((ip ,port ))
                if result ==0 :
                    open_ports .append (port )
            except Exception :
                pass
            finally :
                s .close ()

        return open_ports

    def _classify_threat (self ,abuse_info :Dict ,open_ports :List [int ])->str :
        """Phân loại hình thái đối thủ dựa trên dữ liệu trinh sát."""
        score =abuse_info .get ("abuseConfidenceScore",0 )
        has_proxy_ports =any (p in [1080 ,3128 ,8080 ]for p in open_ports )
        has_telnet =23 in open_ports

        if has_telnet :
            return "Compromised IoT / Botnet Node (Mirai-like variant)"
        if has_proxy_ports :
            return "Anonymized Attacker (Tor Exit Node or Compromised SOCKS Proxy)"
        if score >75 :
            return "Known Malicious Cybercrime / Automated Scanner Infrastructure"
        if score >20 :
            return "Suspicious Host (Frequent scanner)"
        return "Unknown Target / Targeted Reconnaissance"
