"""
Script: test_pipeline.py
Mục đích: Chạy kiểm thử toàn bộ luồng SOAR & Phân tích Trinh sát ngược dựa trên dữ liệu mẫu vừa sinh ra.
"""

import os
import sys

if sys .platform .startswith ("win"):
    try :
        sys .stdout .reconfigure (encoding ="utf-8")
    except Exception :
        pass


sys .path .insert (0 ,os .path .abspath (os .path .join (os .path .dirname (__file__ ),"..")))

from main import MiniSOCActiveDefenseOrchestrator


def main ():
    print ("[*] KHỞI ĐỘNG KIỂM THỬ TOÀN DIỆN HỆ THỐNG SOAR & ACTIVE DEFENSE...")
    orchestrator =MiniSOCActiveDefenseOrchestrator ()

    count =0
    for event in orchestrator .listener .read_historical_events ():
        orchestrator .on_cowrie_event (event )
        count +=1

    print (f"\n[+] ĐÃ HOÀN TẤT KIỂM THỬ: Xử lý thành công {count } sự kiện log Honeypot!")
    print (f"[+] Danh sách IP bị SOAR chặn: {list (orchestrator .enforcer .blocked_ips .keys ())}")


if __name__ =="__main__":
    main ()
