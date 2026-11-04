"""
Module: canary_server.py
Mục đích: Máy chủ Bẫy Mồi Khử Ẩn Danh (Active De-anonymization Canary Webhook Server).
Lắng nghe trên cổng HTTP (mặc định 8080) để hứng các kết nối từ Honeytoken mà hacker đánh cắp:
- Khi hacker lấy trộm file .aws/credentials, .bash_history hoặc db_backup.sql và chạy trên máy thật của chúng:
- Lệnh curl/wget hoặc click link sẽ gửi HTTP request về máy chủ này.
- Máy chủ sẽ lật tẩy IP THẬT (Real IP) của hacker (ngay cả khi chúng dùng VPN/Proxy để SSH vào Honeypot trước đó).
- Lập tức kích hoạt cảnh báo SOAR và thông báo về Telegram!
"""

from datetime import datetime ,timezone
from http .server import BaseHTTPRequestHandler ,HTTPServer
import json
import os
import threading
from typing import Callable ,Optional


class CanaryHTTPRequestHandler (BaseHTTPRequestHandler ):
    def log_message (self ,format ,*args ):

        pass

    def do_GET (self ):
        self ._handle_canary_hit ()

    def do_POST (self ):
        self ._handle_canary_hit ()

    def _handle_canary_hit (self ):

        real_ip =self .client_address [0 ]

        if "X-Forwarded-For"in self .headers :
            real_ip =self .headers ["X-Forwarded-For"].split (",")[0 ].strip ()

        user_agent =self .headers .get ("User-Agent","Unknown Tool")
        request_path =self .path


        token_type ="Tài liệu Bí mật Mồi (Generic Honeytoken)"
        if "patch"in request_path or "history"in request_path :
            token_type ="Lệnh Patch bí mật trong .bash_history (T1552)"
        elif "aws"in request_path :
            token_type ="Khóa AWS Credentials trong /root/.aws/credentials (T1552.001)"
        elif "db"in request_path or "sql"in request_path or "admin"in request_path :
            token_type ="Link Quản trị trong db_backup.sql (T1552)"

        print ("[SOAR ACTIVE DEFENSE - KHỬ ẨN DANH THÀNH CÔNG!]")
        print (f"• Loại bẫy: {token_type }")
        print (f"• IP THẬT CỦA HACKER (Real IP): {real_ip }")
        print (f"• Công cụ / User-Agent: {user_agent }")
        print (f"• Đường dẫn bị gọi: {request_path }")


        if hasattr (self .server ,"alert_callback")and self .server .alert_callback :
            self .server .alert_callback ({
            "eventid":"honeytoken.canary.beacon",
            "src_ip":real_ip ,
            "token_type":token_type ,
            "user_agent":user_agent ,
            "url":request_path ,
            "timestamp":datetime .now (timezone .utc ).isoformat (),
            })


        self .send_response (200 )
        if "patch"in request_path :
            self .send_header ("Content-Type","text/plain")
            self .end_headers ()
            self .wfile .write (b"#!/bin/bash\n# Corporate Security Patch v2.4.1\necho '[+] Applying security patch... Done.'\n")
        else :
            self .send_header ("Content-Type","text/html; charset=utf-8")
            self .end_headers ()
            html =(
            "<html><head><title>Internal Corporate SSO Portal</title></head>"
            "<body style='font-family:sans-serif; text-align:center; padding-top:50px;'>"
            "<h2>403 - Forbidden: Access Denied</h2>"
            "<p>Your client certificate is invalid. This security incident has been logged.</p>"
            "</body></html>"
            )
            self .wfile .write (html .encode ("utf-8"))


class CanaryServer :
    def __init__ (self ,host :str ="0.0.0.0",port :int =8080 ,alert_callback :Optional [Callable [[dict ],None ]]=None ):
        self .host =host
        self .port =port
        self .alert_callback =alert_callback
        self .server :Optional [HTTPServer ]=None
        self .is_running =False
        self ._thread :Optional [threading .Thread ]=None

    def start (self ):
        try :
            self .server =HTTPServer ((self .host ,self .port ),CanaryHTTPRequestHandler )
            self .server .alert_callback =self .alert_callback
            self .is_running =True
            print (f"[CANARY SERVER] Webhook Khử ẩn danh đang lắng nghe tại: http://{self .host }:{self .port }")
            self .server .serve_forever ()
        except Exception as e :
            print (f"[-] Không thể khởi động Canary Server trên port {self .port }: {e }")

    def start_background (self ):
        self ._thread =threading .Thread (target =self .start ,daemon =True )
        self ._thread .start ()

    def stop (self ):
        self .is_running =False
        if self .server :
            try :
                self .server .shutdown ()
                self .server .server_close ()
            except Exception :
                pass
