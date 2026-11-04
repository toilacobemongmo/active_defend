"""
Module: honeytoken_manager.py
Mục đích: Module Quản lý Bẫy Mồi & Khử Ẩn Danh Kẻ Tấn Công (Honeytokens & Active De-anonymization).
Triển khai kỹ thuật gài bẫy tài liệu mồi (Breadcrumbs, Canary Tokens, Fake Credentials) bên trong Honeypot.
Khi hacker đánh cắp và kích hoạt, bẫy sẽ beacon ngược về máy chủ SOC để lật tẩy IP thật và công cụ của chúng.
"""

import os
import uuid
from typing import Dict ,List


class HoneytokenManager :
    def __init__ (self ,callback_base_url :str ="http://my-soc-active-defense.edu.vn/beacon"):
        self .callback_base_url =callback_base_url
        self .active_tokens :Dict [str ,Dict ]={}

    def generate_canary_id (self ,token_type :str )->str :
        """Tạo định danh duy nhất cho từng con token mồi."""
        token_id =f"canary_{token_type }_{uuid .uuid4 ().hex [:8 ]}"
        return token_id

    def create_fake_aws_credentials (self )->str :
        """Tạo file credentials AWS giả lập có nhúng URL kiểm tra mồi."""
        token_id =self .generate_canary_id ("aws")
        beacon_url =f"{self .callback_base_url }?token={token_id }&type=aws"

        content =f"""# AWS Credentials - Generated for Production Database Backup Agent
[default]
aws_access_key_id = AKIAIOSFODNN7{token_id .upper ()}
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
# Internal Verification Endpoint (Do not expose):
# {beacon_url }
region = ap-southeast-1
"""
        self .active_tokens [token_id ]={
        "type":"AWS_CREDENTIAL",
        "file":"/root/.aws/credentials",
        "beacon_url":beacon_url ,
        "status":"ARMED",
        }
        return content

    def create_fake_bash_history (self )->str :
        """Tạo lịch sử dòng lệnh giả lập, nhử hacker chạy lệnh curl/wget bí mật."""
        token_id =self .generate_canary_id ("history")
        beacon_url =f"{self .callback_base_url }/update_patch_{token_id }.sh"

        content =f"""ls -la
cd /var/www/html
git status
docker ps
cat /etc/passwd
# Download internal patch for critical zero-day:
curl -s {beacon_url } | bash
sudo systemctl restart nginx
exit
"""
        self .active_tokens [token_id ]={
        "type":"BASH_HISTORY_BEACON",
        "file":"/root/.bash_history",
        "beacon_url":beacon_url ,
        "status":"ARMED",
        }
        return content

    def create_fake_database_backup (self )->str :
        """Tạo file dump SQL giả lập chứa tài khoản admin và link xác thực nội bộ."""
        token_id =self .generate_canary_id ("sql")
        beacon_url =f"{self .callback_base_url }/verify_admin?token={token_id }"

        content =f"""-- MySQL dump 10.13  Distrib 8.0.32, for Linux (x86_64)
-- Host: internal-db-cluster    Database: enterprise_core
-- ------------------------------------------------------
-- Table structure for table `tbl_admin_users`
INSERT INTO `tbl_admin_users` VALUES
(1, 'superadmin', '$2a$12$e8ZbzM/Yk4X3vXG6Zp5Qle', 'admin@corp.internal', 'ACTIVE'),
(2, 'db_replicator', 'P@ssw0rd2026!SecureKey', 'sync@corp.internal', 'ACTIVE');

-- Internal SSO Authentication Portal:
-- Access link: {beacon_url }
"""
        self .active_tokens [token_id ]={
        "type":"DATABASE_DUMP_CANARY",
        "file":"/var/backups/db_backup_2026.sql",
        "beacon_url":beacon_url ,
        "status":"ARMED",
        }
        return content

    def deploy_tokens_to_honeypot_filesystem (self ,target_dir :str )->List [str ]:
        """Triển khai các file mồi vào filesystem giả lập của Cowrie."""
        deployed_files =[]
        os .makedirs (os .path .join (target_dir ,"root",".aws"),exist_ok =True )
        os .makedirs (os .path .join (target_dir ,"var","backups"),exist_ok =True )


        aws_path =os .path .join (target_dir ,"root",".aws","credentials")
        with open (aws_path ,"w",encoding ="utf-8")as f :
            f .write (self .create_fake_aws_credentials ())
        deployed_files .append (aws_path )


        history_path =os .path .join (target_dir ,"root",".bash_history")
        with open (history_path ,"w",encoding ="utf-8")as f :
            f .write (self .create_fake_bash_history ())
        deployed_files .append (history_path )


        db_path =os .path .join (target_dir ,"var","backups","db_backup_2026.sql")
        with open (db_path ,"w",encoding ="utf-8")as f :
            f .write (self .create_fake_database_backup ())
        deployed_files .append (db_path )

        return deployed_files

    def process_beacon_callback (self ,token_id :str ,request_headers :Dict ,real_ip :str )->Dict :
        """
        Xử lý khi bẫy phát nổ (Kẻ tấn công mở link hoặc sử dụng token).
        Lấy được IP THẬT của kẻ tấn công, trình duyệt thật (User-Agent), và bỏ qua hoàn toàn proxy/botnet!
        """
        token_info =self .active_tokens .get (token_id ,{})
        token_info ["status"]="TRIGGERED"
        token_info ["trigger_ip"]=real_ip
        token_info ["user_agent"]=request_headers .get ("User-Agent","Unknown")

        return {
        "alert":"HONEYTOKEN_TRIGGERED",
        "severity":"CRITICAL",
        "message":f"Kẻ tấn công đã mang tài liệu bẫy ({token_info .get ('type')}) về máy thật để mở!",
        "attacker_real_ip":real_ip ,
        "attacker_fingerprint":request_headers .get ("User-Agent"),
        "token_details":token_info ,
        }
