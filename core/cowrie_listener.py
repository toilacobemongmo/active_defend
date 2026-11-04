"""
Module: cowrie_listener.py
Mục đích: Theo dõi và phân tích luồng sự kiện (event stream) từ tệp log cowrie.json thời gian thực.
Hỗ trợ cả chế độ tail-f thời gian thực và chế độ giả lập xử lý theo batch.
"""

import json
import os
import time
from typing import Callable ,Generator ,Optional


class CowrieLogListener :
    def __init__ (self ,log_file_path :str ,poll_interval :float =0.5 ):
        self .log_file_path =log_file_path
        self .poll_interval =poll_interval
        self ._running =False
        self ._last_position =0

    def start (self ,callback :Callable [[dict ],None ],replay_existing :bool =True )->None :
        """Bắt đầu lắng nghe sự kiện từ file log và chuyển qua hàm callback xử lý.
        Nếu replay_existing=True, nạp các sự kiện đã có trước đó trước khi tail sự kiện mới."""
        self ._running =True


        os .makedirs (os .path .dirname (os .path .abspath (self .log_file_path )),exist_ok =True )
        if not os .path .exists (self .log_file_path ):
            with open (self .log_file_path ,"w",encoding ="utf-8")as f :
                pass

        with open (self .log_file_path ,"r",encoding ="utf-8")as f :
            if not replay_existing :

                f .seek (0 ,os .SEEK_END )
            self ._last_position =f .tell ()

            while self ._running :
                line =f .readline ()
                if not line :
                    time .sleep (self .poll_interval )
                    continue

                line =line .strip ()
                if not line :
                    continue

                try :
                    event =json .loads (line )
                    callback (event )
                except json .JSONDecodeError :

                    continue

    def stop (self )->None :
        """Dừng tiến trình lắng nghe log."""
        self ._running =False

    def read_historical_events (self ,limit :Optional [int ]=None )->Generator [dict ,None ,None ]:
        """Đọc lại toàn bộ lịch sử log đã có sẵn để phân tích thống kê."""
        if not os .path .exists (self .log_file_path ):
            return

        count =0
        with open (self .log_file_path ,"r",encoding ="utf-8")as f :
            for line in f :
                line =line .strip ()
                if not line :
                    continue
                try :
                    event =json .loads (line )
                    yield event
                    count +=1
                    if limit and count >=limit :
                        break
                except json .JSONDecodeError :
                    continue
