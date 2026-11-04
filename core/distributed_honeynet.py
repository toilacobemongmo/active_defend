"""
Module: distributed_honeynet.py
Mục đích: Kiến trúc Mạng Bẫy Mồi Phân Tán (Distributed Honeynet Architecture).
Bao gồm:
1. DistributedSensorNode: Edge Honeypot Sensor Agent triển khai tại các phân vùng mạng (DMZ, Cloud, Internal LAN, Branch).
2. DistributedHoneynetCollector: Bộ thu thập và điều phối sự kiện tập trung (Central Event Collector & Health Monitor).
3. Cross-Sensor Correlation: Tương quan phát hiện kẻ tấn công dò quét xuyên phân vùng mạng (Distributed Cross-Subnet Scanning).
"""

from dataclasses import dataclass ,field
from datetime import datetime ,timezone
import hashlib
import hmac
from http .server import BaseHTTPRequestHandler ,HTTPServer
import json
import os
import threading
import time
from typing import Callable ,Dict ,List ,Optional
import urllib .request


@dataclass
class SensorMetadata :
    node_id :str
    subnet :str
    location :str
    node_type :str
    last_heartbeat :float =field (default_factory =time .time )
    events_reported :int =0
    status :str ="ONLINE"


class DistributedHoneynetCollector :
    """
    Bộ điều phối & thu thập sự kiện tập trung từ các node Honeypot phân tán.
    Lắng nghe REST API từ các Edge Sensors, xác thực Token và chuyển tiếp vào Correlation Engine.
    """

    def __init__ (
    self ,
    host :str ="0.0.0.0",
    port :int =9090 ,
    shared_secret :str ="honeynet_cluster_secret_token_2026",
    event_callback :Optional [Callable [[dict ],None ]]=None ,
    ):
        self .host =host
        self .port =port
        self .shared_secret =shared_secret
        self .event_callback =event_callback
        self .sensors :Dict [str ,SensorMetadata ]={}
        self .ip_targeted_nodes :Dict [str ,set ]={}
        self .server :Optional [HTTPServer ]=None
        self ._thread :Optional [threading .Thread ]=None
        self .is_running =False

    def register_or_heartbeat (self ,node_id :str ,subnet :str ,location :str ,node_type :str )->dict :
        """Đăng ký hoặc cập nhật trạng thái sống (heartbeat) từ một Edge Sensor."""
        now =time .time ()
        if node_id not in self .sensors :
            self .sensors [node_id ]=SensorMetadata (
            node_id =node_id ,
            subnet =subnet ,
            location =location ,
            node_type =node_type ,
            last_heartbeat =now ,
            events_reported =0 ,
            status ="ONLINE",
            )
            try :
                print (f"[DISTRIBUTED HONEYNET] Connected new Sensor: [{node_id }] at {subnet } ({location })")
            except Exception :
                pass
        else :
            sensor =self .sensors [node_id ]
            sensor .last_heartbeat =now
            sensor .status ="ONLINE"

        return {"status":"acknowledged","node_id":node_id ,"timestamp":now }

    def ingest_sensor_event (self ,payload :dict )->dict :
        """Tiếp nhận sự kiện từ Edge Sensor, xác thực và đẩy vào pipeline SOAR."""
        node_id =payload .get ("node_id","unknown-sensor")
        event =payload .get ("event",{})
        src_ip =event .get ("src_ip","0.0.0.0")

        if node_id in self .sensors :
            self .sensors [node_id ].events_reported +=1
            self .sensors [node_id ].last_heartbeat =time .time ()
            event ["sensor_metadata"]={
            "node_id":node_id ,
            "subnet":self .sensors [node_id ].subnet ,
            "location":self .sensors [node_id ].location ,
            }
        else :
            event ["sensor_metadata"]={"node_id":node_id ,"subnet":"dynamic","location":"remote"}


        if src_ip not in self .ip_targeted_nodes :
            self .ip_targeted_nodes [src_ip ]=set ()
        self .ip_targeted_nodes [src_ip ].add (node_id )
        event ["targeted_nodes_count"]=len (self .ip_targeted_nodes [src_ip ])

        if self .event_callback :
            self .event_callback (event )

        return {"status":"accepted","node_id":node_id ,"src_ip":src_ip }

    def get_topology_status (self )->List [dict ]:
        """Trả về danh sách trạng thái của toàn bộ cụm sensor phân tán."""
        now =time .time ()
        topology =[]
        for s in self .sensors .values ():
            status ="ONLINE"if (now -s .last_heartbeat )<60 else "OFFLINE"
            s .status =status
            topology .append ({
            "node_id":s .node_id ,
            "subnet":s .subnet ,
            "location":s .location ,
            "node_type":s .node_type ,
            "events_reported":s .events_reported ,
            "last_seen_sec":int (now -s .last_heartbeat ),
            "status":status ,
            })
        return topology

    def start_background (self ):
        """Khởi chạy HTTP REST Collector trên luồng riêng biệt."""
        collector =self

        class CollectorHandler (BaseHTTPRequestHandler ):
            def log_message (self ,format ,*args ):
                pass

            def _authenticate (self )->bool :
                token =self .headers .get ("X-Honeynet-Token","")
                return hmac .compare_digest (token ,collector .shared_secret )

            def do_GET (self ):
                if self .path =="/api/v1/sensors":
                    topo =collector .get_topology_status ()
                    self .send_response (200 )
                    self .send_header ("Content-Type","application/json")
                    self .end_headers ()
                    self .wfile .write (json .dumps (topo ,ensure_ascii =False ).encode ("utf-8"))
                else :
                    self .send_response (404 )
                    self .end_headers ()

            def do_POST (self ):
                if not self ._authenticate ():
                    self .send_response (401 )
                    self .end_headers ()
                    self .wfile .write (b'{"error": "Unauthorized"}\n')
                    return

                length =int (self .headers .get ("Content-Length",0 ))
                body =self .rfile .read (length ).decode ("utf-8")
                try :
                    data =json .loads (body )
                except Exception :
                    self .send_response (400 )
                    self .end_headers ()
                    return

                if self .path =="/api/v1/sensor/heartbeat":
                    res =collector .register_or_heartbeat (
                    node_id =data .get ("node_id","node"),
                    subnet =data .get ("subnet","10.0.0.0/24"),
                    location =data .get ("location","Unknown Subnet"),
                    node_type =data .get ("node_type","SSH_HONEYPOT"),
                    )
                    self .send_response (200 )
                    self .send_header ("Content-Type","application/json")
                    self .end_headers ()
                    self .wfile .write (json .dumps (res ).encode ("utf-8"))

                elif self .path =="/api/v1/sensor/event":
                    res =collector .ingest_sensor_event (data )
                    self .send_response (200 )
                    self .send_header ("Content-Type","application/json")
                    self .end_headers ()
                    self .wfile .write (json .dumps (res ).encode ("utf-8"))

                else :
                    self .send_response (404 )
                    self .end_headers ()

        self .server =HTTPServer ((self .host ,self .port ),CollectorHandler )
        self .is_running =True
        self ._thread =threading .Thread (target =self .server .serve_forever ,daemon =True )
        self ._thread .start ()
        try :
            print (f"[DISTRIBUTED HONEYNET] Central Collector listening at: http://{self .host }:{self .port }")
        except Exception :
            pass

    def stop (self ):
        """Dừng collector server."""
        if self .server :
            self .server .shutdown ()
            self .server .server_close ()
        self .is_running =False


class DistributedSensorNode :
    """
    Sensor Agent gọn nhẹ chạy tại các phân vùng mạng (DMZ, Branch, Cloud).
    Đóng gói sự kiện và chuyển tiếp bảo mật về Central Collector.
    """

    def __init__ (
    self ,
    node_id :str ,
    subnet :str ,
    location :str ,
    collector_url :str ="http://127.0.0.1:9090",
    shared_secret :str ="honeynet_cluster_secret_token_2026",
    node_type :str ="SSH_HIGH_INTERACTION",
    ):
        self .node_id =node_id
        self .subnet =subnet
        self .location =location
        self .collector_url =collector_url .rstrip ("/")
        self .shared_secret =shared_secret
        self .node_type =node_type
        self .is_running =False
        self ._heartbeat_thread :Optional [threading .Thread ]=None

    def send_heartbeat (self )->bool :
        """Gửi nhịp tim (heartbeat) về Central Collector."""
        url =f"{self .collector_url }/api/v1/sensor/heartbeat"
        payload =json .dumps ({
        "node_id":self .node_id ,
        "subnet":self .subnet ,
        "location":self .location ,
        "node_type":self .node_type ,
        "timestamp":time .time (),
        }).encode ("utf-8")

        req =urllib .request .Request (
        url ,
        data =payload ,
        headers ={
        "Content-Type":"application/json",
        "X-Honeynet-Token":self .shared_secret ,
        },
        method ="POST",
        )
        try :
            with urllib .request .urlopen (req ,timeout =3 )as resp :
                return resp .status ==200
        except Exception :
            return False

    def forward_event (self ,event :dict )->bool :
        """Chuyển tiếp sự kiện từ sensor về bộ điều phối trung tâm."""
        url =f"{self .collector_url }/api/v1/sensor/event"
        payload =json .dumps ({
        "node_id":self .node_id ,
        "event":event ,
        "timestamp":datetime .now (timezone .utc ).isoformat (),
        }).encode ("utf-8")

        req =urllib .request .Request (
        url ,
        data =payload ,
        headers ={
        "Content-Type":"application/json",
        "X-Honeynet-Token":self .shared_secret ,
        },
        method ="POST",
        )
        try :
            with urllib .request .urlopen (req ,timeout =3 )as resp :
                return resp .status ==200
        except Exception as e :
            return False

    def start_heartbeat_loop (self ,interval_sec :int =15 ):
        """Khởi động luồng gửi heartbeat định kỳ."""
        self .is_running =True

        def _loop ():
            while self .is_running :
                self .send_heartbeat ()
                time .sleep (interval_sec )

        self ._heartbeat_thread =threading .Thread (target =_loop ,daemon =True )
        self ._heartbeat_thread .start ()

    def stop (self ):
        self .is_running =False
