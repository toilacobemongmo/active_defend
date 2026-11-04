"""
Web SOC Dashboard: Giao diện Trung tâm Điều hành An ninh Mạng (Mini-SOC & SOAR Dashboard).
Chạy bằng Streamlit: streamlit run scripts/dashboard.py
Phiên bản nâng cấp:
- Dynamic Threat Risk Scoring Gauge (Đánh giá mức độ rủi ro IP thời gian thực)
- Interactive Attacker Session Terminal Replay (Xem lại thao tác hacker gõ lệnh)
- Multi-tier SOAR Defense Matrix (Adaptive Jail, STIX 2.1 Indicators & Snort Rules)
"""

from datetime import datetime
import json
import os
import sys
import time
import pandas as pd
import streamlit as st


sys .path .insert (0 ,os .path .abspath (os .path .join (os .path .dirname (__file__ ),"..")))

from core .correlation_engine import EventCorrelationEngine
from core .reverse_intel import ReverseIntelligenceEngine

st .set_page_config (
page_title ="Mini-SOC Active Defense & SOAR Dashboard",
page_icon ="",
layout ="wide",
initial_sidebar_state ="expanded",
)

LOG_PATH =os .path .abspath ("./data/cowrie.json")
STIX_PATH =os .path .abspath ("./data/stix_indicators.json")
SNORT_PATH =os .path .abspath ("./data/honeynet_snort_rules.rules")


def load_events ():
    events =[]
    if os .path .exists (LOG_PATH ):
        with open (LOG_PATH ,"r",encoding ="utf-8")as f :
            for line in f :
                line =line .strip ()
                if line :
                    try :
                        events .append (json .loads (line ))
                    except Exception :
                        pass
    return events


def analyze_events (events ):
    engine =EventCorrelationEngine (brute_force_threshold =5 ,window_seconds =60 )
    alerts =[]
    blocked_ips =set ()
    honeytoken_hits =0

    for evt in events :
        alert =engine .process_event (evt )
        if alert :
            alerts .append (alert )
            if "block"in alert .recommended_action :
                blocked_ips .add (alert .source_ip )
            if "Honeytoken"in alert .rule_name or "CANARY"in alert .alert_id :
                honeytoken_hits +=1

    return alerts ,blocked_ips ,honeytoken_hits ,engine


st .sidebar .image ("https://img.icons8.com/color/96/shield.png",width =70 )
st .sidebar .title ("Mini-SOC Control")
st .sidebar .markdown ("**Active Defense & Multi-tier SOAR**")
st .sidebar .markdown ("---")

st .sidebar .markdown ("###  Kích hoạt Tấn công Giả lập")
if st .sidebar .button (" Chạy 4 Kịch bản Red Team",type ="primary"):
    with st .spinner ("Đang bắn kịch bản tấn công mẫu vào Honeypot..."):
        from scripts .simulate_attack import (
        simulate_scenario_1_bruteforce ,
        simulate_scenario_2_login_and_recon ,
        simulate_scenario_3_honeytoken_breach ,
        simulate_scenario_4_malware_drop ,
        )
        simulate_scenario_1_bruteforce ()
        simulate_scenario_2_login_and_recon ()
        simulate_scenario_3_honeytoken_breach ()
        simulate_scenario_4_malware_drop ()
        st .sidebar .success ("Đã sinh 4 kịch bản tấn công thành công!")
        st .rerun ()

if st .sidebar .button (" Làm mới dữ liệu (Refresh)"):
    st .rerun ()

st .sidebar .markdown ("---")
st .sidebar .markdown ("###  Kết nối SSH Honeypot")
st .sidebar .code ("ssh root@127.0.0.1 -p 2222\n# Pass: monkey",language ="bash")


events =load_events ()
alerts ,blocked_ips ,honeytoken_hits ,correlation_engine =analyze_events (events )

st .title (" Trung tâm Điều hành An ninh Mạng Chủ động (Mini-SOC & SOAR)")
st .caption ("Tích hợp SSH Deception, Dynamic Risk Scoring, Terminal Forensics Replay & Multi-tier SOAR")


col1 ,col2 ,col3 ,col4 ,col5 =st .columns (5 )
col1 .metric ("Tổng sự kiện Cowrie",f"{len (events ):,}",delta ="Raw Telemetry")
col2 .metric ("Sự cố MITRE ATT&CK",f"{len (alerts ):,}",delta ="Correlated",delta_color ="inverse")
col3 .metric ("Tarpit & Firewall Block",f"{len (blocked_ips )}",delta ="Multi-Tier SOAR",delta_color ="inverse")
col4 .metric ("Bẫy Honeytoken nổ",f"{honeytoken_hits }",delta ="De-anonymized",delta_color ="inverse")


max_risk =max ([p ["score"]for p in correlation_engine .ip_risk_profiles .values ()])if correlation_engine .ip_risk_profiles else 0
col5 .metric ("Max Dynamic Risk Score",f"{max_risk }/100",delta ="Critical IP"if max_risk >=75 else "Elevated",delta_color ="inverse")

st .markdown ("---")

tab1 ,tab2 ,tab3 ,tab4 ,tab5 =st .tabs ([
" Danh sách Sự cố & Dynamic Risk Score",
" Terminal Forensics & Session Replay",
" Trinh sát ngược & Tình báo OSINT",
" Chia sẻ Tình báo Quốc tế (STIX 2.1 & Snort)",
" Nhật ký Raw Honeypot Log",
])

with tab1 :
    st .subheader ("Cảnh báo Sự cố được Chấm điểm Nguy cơ Động (Dynamic Risk Score)")
    if not alerts :
        st .info ("Chưa có sự cố nào. Bấm nút 'Chạy 4 Kịch bản Red Team' ở thanh bên trái hoặc SSH vào port 2222!")
    else :
        table_data =[]
        for a in reversed (alerts ):
            table_data .append ({
            "Mã sự cố":a .alert_id ,
            "Thời gian":a .timestamp ,
            "Mức độ":a .severity ,
            "Risk Score":f"{a .risk_score }/100",
            "Quy tắc phát hiện":a .rule_name ,
            "Kỹ thuật MITRE":f"{a .mitre_technique_id } - {a .mitre_technique_name }",
            "IP Tấn công":a .source_ip ,
            "Hành động SOAR":a .recommended_action ,
            })
        df_alerts =pd .DataFrame (table_data )

        def color_severity (val ):
            if val =="CRITICAL":
                return "color: #ff4b4b; font-weight: bold;"
            elif val =="HIGH":
                return "color: #ffa421; font-weight: bold;"
            elif val =="MEDIUM":
                return "color: #ffd166; font-weight: bold;"
            return "color: #06d6a0;"

        try :
            st .dataframe (df_alerts .style .map (color_severity ,subset =["Mức độ"]),use_container_width =True ,height =350 )
        except Exception :
            st .dataframe (df_alerts ,use_container_width =True ,height =350 )


        st .markdown ("####  Ma trận Hồ sơ Rủi ro Động theo IP (Dynamic Risk Scoring Profiles)")
        risk_summary =[]
        for ip ,prof in correlation_engine .ip_risk_profiles .items ():
            risk_summary .append ({
            "IP Đối tượng":ip ,
            "Điểm Rủi ro (0-100)":prof ["score"],
            "Số lần vi phạm":prof ["violation_count"],
            "Cấp độ Ứng phó SOAR":prof ["escalation_level"],
            "TTPs đã nhận diện":", ".join (list (prof ["ttps"])[:3 ]),
            })
        if risk_summary :
            st .dataframe (pd .DataFrame (risk_summary ),use_container_width =True )

with tab2 :
    st .subheader (" Pháp y Số: Xem lại Phiên gõ lệnh của Hacker (Terminal Keystroke Replay)")
    st .markdown ("Tính năng ghi nhận toàn bộ chuỗi hành động của hacker sau khi xâm nhập vào Honeypot, phục vụ điều tra số (Forensics).")

    active_sessions =list (correlation_engine .session_recordings .keys ())
    if not active_sessions :

        cmd_events =[e for e in events if e .get ("eventid")=="cowrie.command.input"]
        if cmd_events :
            for ce in cmd_events :
                sid =ce .get ("session","session_demo_1")
                correlation_engine .record_session_keystroke (sid ,ce .get ("src_ip","45.33.32.156"),ce .get ("input",""),ce .get ("timestamp",""))
            active_sessions =list (correlation_engine .session_recordings .keys ())

    if not active_sessions :
        st .info ("Chưa có phiên tương tác dòng lệnh nào. Hãy đăng nhập SSH bẫy hoặc chạy giả lập để ghi lại keystroke!")
    else :
        chosen_session =st .selectbox ("Chọn Session ID cần điều tra & Replay:",active_sessions )
        replay_logs =correlation_engine .session_recordings .get (chosen_session ,[])

        col_s1 ,col_s2 =st .columns ([1 ,2 ])
        with col_s1 :
            st .markdown ("#####  Thông tin Phiên")
            if replay_logs :
                st .write (f"• **Session ID:** `{chosen_session }`")
                st .write (f"• **IP Nguồn:** `{replay_logs [0 ]['ip']}`")
                st .write (f"• **Tổng số lệnh đã gõ:** `{len (replay_logs )}`")
                st .write (f"• **Thời gian bắt đầu:** `{replay_logs [0 ]['timestamp']}`")

        with col_s2 :
            st .markdown ("#####  Mô phỏng Màn hình Terminal (Asciinema Style)")
            terminal_box =st .empty ()
            prompt_prefix ="root@ubuntu-srv:~# "


            term_content =""
            for item in replay_logs :
                term_content +=f"{prompt_prefix }{item ['command']}\n"

            st .code (term_content if term_content else "# Trống",language ="bash")

with tab3 :
    st .subheader ("Trinh sát ngược (Reverse Reconnaissance & OSINT)")
    unique_ips =list (set ([a .source_ip for a in alerts if a .source_ip not in ("0.0.0.0","127.0.0.1")]))
    if not unique_ips :
        unique_ips =["185.220.101.5","45.33.32.156","103.20.144.12","194.87.139.12"]

    selected_ip =st .selectbox ("Chọn IP đối phương cần trinh sát:",unique_ips )
    if selected_ip :
        rev_engine =ReverseIntelligenceEngine ()
        with st .spinner (f"Đang trinh sát ngược IP {selected_ip }..."):
            recon =rev_engine .gather_full_recon (selected_ip )

        r_col1 ,r_col2 =st .columns (2 )
        with r_col1 :
            st .markdown ("####  Thông tin Định vị & Mạng (GeoIP)")
            geo =recon .get ("geo_intel",{})
            st .write (f"• **Quốc gia:** {geo .get ('country','N/A')} ({geo .get ('countryCode','N/A')})")
            st .write (f"• **Thành phố:** {geo .get ('city','N/A')}")
            st .write (f"• **Nhà mạng (ISP):** {geo .get ('isp','N/A')}")
            st .write (f"• **Tổ chức (Org):** {geo .get ('org','N/A')}")
            st .write (f"• **ASN:** {geo .get ('as','N/A')}")

        with r_col2 :
            st .markdown ("####  Danh tiếng Nguy hại & Nhận diện")
            rep =recon .get ("reputation",{})
            score =rep .get ("abuseConfidenceScore",0 )
            st .write (f"• **Điểm độc hại AbuseIPDB:** `{score }%`")
            st .progress (score /100 )
            st .write (f"• **Số lượt báo cáo toàn cầu:** {rep .get ('totalReports','N/A')}")
            st .write (f"• **Cổng dịch vụ quét được:** `{recon .get ('active_services',[])}`")
            st .write (f"• **Phân loại đối thủ:** **{recon .get ('threat_classification','Unknown')}**")

with tab4 :
    st .subheader (" Chia sẻ Tình báo Mối Đe Dọa (STIX 2.1 & Snort IDS Rule Export)")
    st .markdown ("Khả năng tích hợp với hệ thống bên thứ ba: Xuất IoC chuẩn quốc tế OASIS STIX 2.1 và tự động sinh luật bảo vệ NIDS Snort/Suricata.")

    st_col1 ,st_col2 =st .columns (2 )
    with st_col1 :
        st .markdown ("#####  OASIS STIX 2.1 Indicators (`data/stix_indicators.json`)")
        if os .path .exists (STIX_PATH ):
            try :
                with open (STIX_PATH ,"r",encoding ="utf-8")as f :
                    stix_data =json .load (f )
                st .json (stix_data [-3 :]if len (stix_data )>3 else stix_data )
            except Exception as e :
                st .code (f"Chưa có dữ liệu STIX: {e }")
        else :
            st .info ("Chưa có tệp STIX. Khi SOAR kích hoạt chặn IP, tệp STIX 2.1 sẽ tự động xuất bản!")

    with st_col2 :
        st .markdown ("#####  Snort / Suricata IDS Rules (`data/honeynet_snort_rules.rules`)")
        if os .path .exists (SNORT_PATH ):
            with open (SNORT_PATH ,"r",encoding ="utf-8")as f :
                snort_rules =f .read ()
            st .code (snort_rules if snort_rules else "# Chưa có rules",language ="bash")
        else :
            st .info ("Chưa có Snort Rules. Sẽ tự động sinh khi SOAR Enforcer phát hiện hành vi nguy hại!")

with tab5 :
    st .subheader ("Nhật ký Luồng Sự kiện Thô (Raw Cowrie Log Feed)")
    if not events :
        st .write ("File log trống.")
    else :
        st .dataframe (pd .DataFrame (list (reversed (events [-50 :]))),use_container_width =True ,height =400 )
