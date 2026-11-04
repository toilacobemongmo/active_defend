"""
Main Orchestrator: Hệ sinh thái Phòng thủ Chủ động (Active Defense & SOAR Ecosystem).
Tích hợp Cowrie SSH Honeypot, Correlation Engine, Reverse Intel, Honeytokens và Telegram SOAR Bot.
"""

import argparse
import os
import sys
import threading
import time
import yaml

if sys .platform .startswith ("win"):
    try :
        sys .stdout .reconfigure (encoding ="utf-8",line_buffering =True )
    except Exception :
        pass
from core .canary_server import CanaryServer
from core .correlation_engine import EventCorrelationEngine ,ThreatAlert
from core .cowrie_listener import CowrieLogListener
from core .honeytoken_manager import HoneytokenManager
from core .mini_ssh_honeypot import MiniSSHHoneypot
from core .payload_analyzer import PayloadAnalyzer
from core .reverse_intel import ReverseIntelligenceEngine
from core .soar_enforcer import SOAREnforcer
from core .distributed_honeynet import DistributedHoneynetCollector ,DistributedSensorNode
from core .telegram_soar_bot import TelegramSOARBot


class MiniSOCActiveDefenseOrchestrator :
    def __init__ (
    self ,
    config_path :str ="config/config.yaml",
    enable_honeypot :bool =True ,
    honeypot_port :int =2222 ,
    enable_canary :bool =True ,
    canary_port :int =8080 ,
    ):
        print ("[*] Đang khởi động Hệ thống Mini-SOC Active Defense & SOAR...")
        self .config =self ._load_config (config_path )
        self .enable_honeypot =enable_honeypot
        self .honeypot_port =honeypot_port
        self .enable_canary =enable_canary
        self .canary_port =canary_port


        whitelist =self .config .get ("soar_rules",{}).get ("firewall_enforcement",{}).get ("whitelist",[])
        self .enforcer =SOAREnforcer (whitelist =whitelist )


        intel_cfg =self .config .get ("threat_intel",{})
        self .reverse_intel =ReverseIntelligenceEngine (
        abuseipdb_key =intel_cfg .get ("abuseipdb",{}).get ("api_key"),
        shodan_key =intel_cfg .get ("shodan",{}).get ("api_key"),
        )


        self .honeytoken_mgr =HoneytokenManager ()


        self .payload_analyzer =PayloadAnalyzer (
        vt_api_key =intel_cfg .get ("virustotal",{}).get ("api_key")
        )


        brute_cfg =self .config .get ("soar_rules",{}).get ("brute_force",{})
        self .correlation_engine =EventCorrelationEngine (
        brute_force_threshold =brute_cfg .get ("threshold_attempts",5 ),
        window_seconds =brute_cfg .get ("time_window_sec",60 ),
        )


        tg_cfg =self .config .get ("telegram",{})
        self .telegram_bot =TelegramSOARBot (
        bot_token =tg_cfg .get ("bot_token",""),
        chat_id =tg_cfg .get ("chat_id",""),
        action_callback =self ._handle_analyst_action ,
        )


        cowrie_log_path =self .config .get ("cowrie",{}).get ("log_path","./data/cowrie.json")
        self .listener =CowrieLogListener (log_file_path =cowrie_log_path )


        self .honeypot =None
        if self .enable_honeypot :
            try :
                self .honeypot =MiniSSHHoneypot (
                port =self .honeypot_port ,
                log_file =cowrie_log_path ,
                soar_enforcer =self .enforcer ,
                event_callback =self .on_cowrie_event ,
                )
            except Exception as e :
                print (f"[!] Không thể khởi tạo SSH Honeypot trên port {self .honeypot_port }: {e }")


        self .canary_server =None
        if self .enable_canary :
            try :
                self .canary_server =CanaryServer (
                port =self .canary_port ,
                alert_callback =self .on_canary_event ,
                )
            except Exception as e :
                print (f"[!] Không thể khởi tạo Canary Webhook Server trên port {self .canary_port }: {e }")


        dist_cfg =self .config .get ("distributed_honeynet",{})
        self .enable_distributed =dist_cfg .get ("enabled",True )
        self .distributed_port =dist_cfg .get ("collector_port",9090 )
        self .distributed_collector =None
        if self .enable_distributed :
            try :
                self .distributed_collector =DistributedHoneynetCollector (
                host =dist_cfg .get ("collector_host","0.0.0.0"),
                port =self .distributed_port ,
                shared_secret =dist_cfg .get ("shared_secret","honeynet_cluster_secret_token_2026"),
                event_callback =self .on_cowrie_event ,
                )
                for node in dist_cfg .get ("sensor_nodes",[]):
                    self .distributed_collector .register_or_heartbeat (
                    node_id =node .get ("node_id"),
                    subnet =node .get ("subnet"),
                    location =node .get ("location"),
                    node_type =node .get ("node_type","SSH_HONEYPOT"),
                    )
            except Exception as e :
                print (f"[!] Không thể khởi tạo Distributed Honeynet Collector trên port {self .distributed_port }: {e }")

        print ("[+] Toàn bộ phân hệ phòng thủ chủ động đã sẵn sàng hoạt động!")

    def on_canary_event (self ,event :dict )->None :
        """Xử lý khi kẻ tấn công sập bẫy Honeytoken khử ẩn danh."""
        real_ip =event .get ("src_ip","Unknown")
        token_type =event .get ("token_type","Honeytoken")
        user_agent =event .get ("user_agent","Unknown")
        url =event .get ("url","")

        recon =self .reverse_intel .gather_full_recon (real_ip )
        alert_dict ={
        "rule_name":f"Khử ẩn danh thành công: Bẫy Honeytoken bị kích hoạt! ({token_type })",
        "source_ip":real_ip ,
        "mitre_id":"T1552.001",
        "mitre_name":"Unsecured Credentials: Real IP De-anonymized",
        "severity":"CRITICAL",
        "timestamp":event .get ("timestamp"),
        "details":{
        "Loại bẫy sập":token_type ,
        "IP Thật của Hacker":real_ip ,
        "Quốc gia/ISP":f"{recon ['geo_intel'].get ('country')} / {recon ['geo_intel'].get ('isp')}",
        "Công cụ Hacker dùng":user_agent ,
        "Điểm độc hại":f"{recon ['reputation'].get ('abuseConfidenceScore',0 )}% (AbuseIPDB)",
        "URL bị gọi":url ,
        },
        "recommended_action":"tarpit_and_block",
        }
        self .telegram_bot .send_incident_alert (alert_dict )

    def _load_config (self ,config_path :str )->dict :
        if not os .path .exists (config_path ):
            raise FileNotFoundError (f"Không tìm thấy file cấu hình tại {config_path }")
        with open (config_path ,"r",encoding ="utf-8")as f :
            cfg =yaml .safe_load (f )or {}


        try :
            from dotenv import load_dotenv
            load_dotenv ()
        except ImportError :
            pass


        tg =cfg .setdefault ("telegram",{})
        if os .getenv ("TELEGRAM_BOT_TOKEN"):
            tg ["bot_token"]=os .getenv ("TELEGRAM_BOT_TOKEN")
        if os .getenv ("TELEGRAM_CHAT_ID"):
            tg ["chat_id"]=os .getenv ("TELEGRAM_CHAT_ID")

        ti =cfg .setdefault ("threat_intel",{})
        if os .getenv ("ABUSEIPDB_API_KEY"):
            ti .setdefault ("abuseipdb",{})["api_key"]=os .getenv ("ABUSEIPDB_API_KEY")
        if os .getenv ("SHODAN_API_KEY"):
            ti .setdefault ("shodan",{})["api_key"]=os .getenv ("SHODAN_API_KEY")
        if os .getenv ("VIRUSTOTAL_API_KEY"):
            ti .setdefault ("virustotal",{})["api_key"]=os .getenv ("VIRUSTOTAL_API_KEY")

        return cfg

    def _handle_analyst_action (self ,action :str ,ip :str )->dict :
        """Xử lý lệnh khi Chuyên viên SOC bấm nút trên Telegram."""
        print (f"\n[!] Nhận lệnh từ Telegram SOC Bot: Hành động '{action }' nhắm vào IP {ip }")

        if action =="recon":
            recon_data =self .reverse_intel .gather_full_recon (ip )
            summary =(
            f"<b>[SOAR] KET QUA TRINH SAT NGUOC IP:</b> <code>{ip }</code>\n"
            f"• Quốc gia: {recon_data ['geo_intel'].get ('country')} ({recon_data ['geo_intel'].get ('city')})\n"
            f"• ISP: {recon_data ['geo_intel'].get ('isp')}\n"
            f"• Điểm độc hại (AbuseIPDB): {recon_data ['reputation'].get ('abuseConfidenceScore',0 )}%\n"
            f"• Cổng dịch vụ mở: {recon_data .get ('active_services')}\n"
            f"• Phân loại đối thủ: <b>{recon_data .get ('threat_classification')}</b>"
            )
            self .telegram_bot .send_simple_message (summary )
            return {"action":"Đã trinh sát ngược và gửi báo cáo tình báo"}

        elif action =="block":
            res =self .enforcer .block_ip (ip ,duration_sec =3600 ,reason ="SOC Analyst Manual Block")
            return res

        elif action =="tarpit":
            res =self .enforcer .tarpit_ip (ip )
            return res

        elif action =="unblock":
            res =self .enforcer .unblock_ip (ip )
            return res

        return {"action":"Không nhận diện được hành động"}

    def on_cowrie_event (self ,event :dict )->None :
        """Xử lý từng sự kiện log từ Cowrie."""
        alert :ThreatAlert =self .correlation_engine .process_event (event )
        if not alert :
            return

        print (f"\n[!] PHÁT HIỆN SỰ CỐ: {alert .rule_name } | IP: {alert .source_ip } | MITRE: {alert .mitre_technique_id }")


        enriched_info ={}
        if alert .severity in ("HIGH","CRITICAL"):
            recon =self .reverse_intel .gather_full_recon (alert .source_ip )
            enriched_info ={
            "Quốc gia/ISP":f"{recon ['geo_intel'].get ('country')} / {recon ['geo_intel'].get ('isp')}",
            "Phân loại hình thái":recon .get ("threat_classification"),
            "Mức độ uy tín độc hại":f"{recon ['reputation'].get ('abuseConfidenceScore',0 )}% (AbuseIPDB)",
            }
            alert .details .update (enriched_info )


        if alert .recommended_action =="tarpit_and_block":
            auto_block =self .config .get ("soar_rules",{}).get ("firewall_enforcement",{}).get ("auto_block",False )
            if auto_block :
                self .enforcer .block_ip (alert .source_ip ,reason ="Automated Brute Force Mitigation")
                alert .details ["Hành động SOAR tự động"]="Đã khóa IP trên Firewall trong 3600s"

        elif alert .recommended_action =="quarantine_and_vt_scan":
            file_path =alert .details .get ("local_sandbox_file")
            if file_path and os .path .exists (file_path ):
                analysis =self .payload_analyzer .analyze_file (file_path )
                alert .details ["Malware Family"]=analysis .get ("malware_family")
                alert .details ["VirusTotal Positives"]=f"{analysis ['virustotal_intel'].get ('positives')}/{analysis ['virustotal_intel'].get ('total')}"


        self .telegram_bot .send_incident_alert ({
        "rule_name":alert .rule_name ,
        "source_ip":alert .source_ip ,
        "mitre_id":alert .mitre_technique_id ,
        "mitre_name":alert .mitre_technique_name ,
        "severity":alert .severity ,
        "timestamp":alert .timestamp ,
        "details":alert .details ,
        "recommended_action":alert .recommended_action ,
        })

    def run (self ,replay_existing :bool =True ,auto_simulate :bool =False )->None :
        """Khởi động toàn bộ luồng hoạt động."""

        if self .honeypot :
            self .honeypot .start_background ()


        if self .canary_server :
            self .canary_server .start_background ()


        if self .distributed_collector :
            self .distributed_collector .start_background ()


        self .telegram_bot .start_polling ()


        if auto_simulate :
            def _async_sim ():
                time .sleep (2.0 )
                try :
                    from scripts .simulate_attack import (
                    simulate_scenario_1_bruteforce ,
                    simulate_scenario_2_login_and_recon ,
                    simulate_scenario_3_honeytoken_breach ,
                    simulate_scenario_4_malware_drop ,
                    )
                    simulate_scenario_1_bruteforce ()
                    time .sleep (1 )
                    simulate_scenario_2_login_and_recon ()
                    time .sleep (1 )
                    simulate_scenario_3_honeytoken_breach ()
                    time .sleep (1 )
                    simulate_scenario_4_malware_drop ()
                except Exception as ex :
                    print (f"[-] Lỗi trong luồng giả lập: {ex }")

            threading .Thread (target =_async_sim ,daemon =True ).start ()

        print ("\n"+"="*76 )
        print ("   [SOAR] HE SINH THAI ACTIVE DEFENSE & SOAR HONEYNET (MINI-SOC LIVE DEMO)")
        print ("="*76 )
        print ("[*] Trạng thái các phân hệ phòng thủ:")
        print ("    • Tương quan sự kiện MITRE ATT&CK : SẴN SÀNG")
        print ("    • Phản ứng sự cố SOAR Enforcer    : SẴN SÀNG (Firewall & Tarpit Active)")
        print ("    • Bẫy mồi chủ động Honeytoken     : SẴN SÀNG (.aws/credentials, db_pass)")
        print ("    • Trinh sát ngược Threat Intel    : SẴN SÀNG (GeoIP / AbuseIPDB)")
        print ("    • Bot tương tác Telegram SOAR     : SẴN SÀNG")
        if self .honeypot :
            print (f"    • Live SSH Honeypot tương tác thật: ĐANG LẮNG NGHE PORT {self .honeypot_port } (0.0.0.0:{self .honeypot_port })")
        if self .canary_server :
            print (f"    • Cổng Webhook Bẫy Khử ẩn danh    : ĐANG LẮNG NGHE PORT {self .canary_port } (http://0.0.0.0:{self .canary_port })")
        if self .distributed_collector :
            print (f"    • Distributed Honeynet Collector  : ĐANG LẮNG NGHE PORT {self .distributed_port } (http://0.0.0.0:{self .distributed_port })")
        print ("-"*76 )
        print ("[+] CAC CACH KIEM THU THUC TE (LIVE DEMO) DE GUI GIANG VIEN:")
        print (f"   [1] KẾT NỐI SSH THẬT VÀO HONEYPOT (Từ cửa sổ Terminal khác):")
        print (f"       ssh root@127.0.0.1 -p {self .honeypot_port if self .honeypot else 2222 }")
        print ("       - Nhập sai mật khẩu liên tục (>5 lần) -> SOAR sẽ tự động khóa IP!")
        print ("       - Đăng nhập 'root' / mật khẩu 'monkey' (hoặc 'ubuntu' / '1234567') để vào shell bẫy mồi:")
        print ("         + Gõ: whoami, uname -a, ps aux")
        print ("         + Gõ lệnh xem bẫy: cat /root/.aws/credentials hoặc cat /root/.bash_history")
        print (f"   [2] TEST KHỬ ẨN DANH HACKER (Canary Honeytoken):")
        print (f"       Mở trình duyệt hoặc curl link Webhook: curl http://127.0.0.1:{self .canary_port }/canary/patch.sh")
        print ("       -> Màn hình SOAR và Telegram sẽ lập tức lật tẩy Real IP của đối phương!")
        print ("   [3] MỞ GIAO DIỆN WEB SOC DASHBOARD TRỰC QUAN:")
        print ("       streamlit run scripts/dashboard.py")
        print ("   [4] HOẶC BẮN LUỒNG GIẢ LẬP TẤN CÔNG RED TEAM:")
        print ("       python scripts/simulate_attack.py")
        print ("="*76 )
        print ("[*] Đang theo dõi sự kiện an ninh... (Nhấn Ctrl+C để dừng)\n")

        try :
            self .listener .start (callback =self .on_cowrie_event ,replay_existing =replay_existing )
        except KeyboardInterrupt :
            print ("\n[-] Đang dừng hệ thống...")
            if self .honeypot :
                self .honeypot .stop ()
            if self .canary_server :
                self .canary_server .stop ()
            if self .distributed_collector :
                self .distributed_collector .stop ()
            self .listener .stop ()


def main ():
    parser =argparse .ArgumentParser (description ="Hệ thống Mini-SOC Active Defense & SOAR Honeynet")
    parser .add_argument ("--port",type =int ,default =2222 ,help ="Cổng chạy SSH Honeypot thật (Mặc định: 2222)")
    parser .add_argument ("--no-honeypot",action ="store_true",help ="Tắt Live SSH Honeypot")
    parser .add_argument ("--canary-port",type =int ,default =8080 ,help ="Cổng Webhook Khử ẩn danh Canary (Mặc định: 8080)")
    parser .add_argument ("--no-canary",action ="store_true",help ="Tắt Cổng Webhook Canary")
    parser .add_argument ("--no-replay",action ="store_true",help ="Không đọc lại các dòng log cũ đã có")
    parser .add_argument ("--simulate",action ="store_true",help ="Tự động bắn 4 kịch bản tấn công ngay sau khi khởi động")
    args =parser .parse_args ()

    orchestrator =MiniSOCActiveDefenseOrchestrator (
    enable_honeypot =not args .no_honeypot ,
    honeypot_port =args .port ,
    enable_canary =not args .no_canary ,
    canary_port =args .canary_port ,
    )
    orchestrator .run (
    replay_existing =not args .no_replay ,
    auto_simulate =args .simulate ,
    )


if __name__ =="__main__":
    main ()
