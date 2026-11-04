"""
Module: telegram_soar_bot.py
Mục đích: Telegram SOAR Bot tương tác 2 chiều (Interactive Security Operations Bot).
Không chỉ gửi cảnh báo một chiều, Bot cung cấp các nút bấm tương tác (Inline Buttons) cho phép chuyên viên SOC:
- Quét ngược IP (Trigger Reverse OSINT)
- Chặn IP lập tức (Firewall Drop)
- Giam lỏng vào Tarpit (Exhaust Resources)
- Mở chặn IP (Whitelist/Release)
"""

import html
import json
import threading
import time
from typing import Callable ,Dict ,Optional
import requests


class TelegramSOARBot :
    def __init__ (self ,bot_token :str ,chat_id :str ,action_callback :Optional [Callable [[str ,str ],Dict ]]=None ):
        self .bot_token =(bot_token or "").strip ()
        self .chat_id =(str (chat_id )if chat_id is not None else "").strip ()
        self .action_callback =action_callback
        self .base_url =f"https://api.telegram.org/bot{self .bot_token }"
        self .last_update_id =0
        self .is_running =False

    def _is_chat_id_valid (self )->bool :
        """Kiểm tra Chat ID đã được định cấu hình hợp lệ hay chưa."""
        return bool (self .chat_id and self .chat_id !="YOUR_TELEGRAM_CHAT_ID")

    def _is_token_valid (self )->bool :
        """Kiểm tra Bot Token có tồn tại hay không."""
        return bool (self .bot_token and self .bot_token !="YOUR_TELEGRAM_BOT_TOKEN")

    def _auto_detect_chat_id (self )->bool :
        """Thử tra cứu getUpdates từ Telegram API để tự nhận diện Chat ID nếu chưa cấu hình."""
        if not self ._is_token_valid ():
            return False

        try :
            url =f"{self .base_url }/getUpdates?limit=10"
            resp =requests .get (url ,timeout =10 )
            if resp .status_code ==200 :
                data =resp .json ()
                for update in reversed (data .get ("result",[])):
                    chat =None
                    if "message"in update :
                        chat =update ["message"].get ("chat",{})
                    elif "channel_post"in update :
                        chat =update ["channel_post"].get ("chat",{})
                    elif "callback_query"in update :
                        chat =update ["callback_query"].get ("message",{}).get ("chat",{})
                    elif "my_chat_member"in update :
                        chat =update ["my_chat_member"].get ("chat",{})

                    if chat and "id"in chat :
                        self .chat_id =str (chat ["id"])
                        print (f"\n[+] Tu dong nhan dien Chat ID Telegram: {self .chat_id }")
                        return True
        except Exception :
            pass

        return False

    def send_incident_alert (self ,alert_data :Dict )->bool :
        """Gửi thẻ cảnh báo sự cố kèm các nút bấm hành động tương tác."""
        if not self ._is_token_valid ():
            self ._print_simulation (alert_data )
            return True

        if not self ._is_chat_id_valid ():

            if not self ._auto_detect_chat_id ():
                self ._print_simulation (alert_data )
                return True

        ip =alert_data .get ("source_ip","0.0.0.0")
        rule_name =alert_data .get ("rule_name","Unknown Alert")
        severity =alert_data .get ("severity","INFO")
        mitre_id =alert_data .get ("mitre_id","N/A")
        mitre_name =alert_data .get ("mitre_name","N/A")
        timestamp =alert_data .get ("timestamp","N/A")
        details =alert_data .get ("details",{})


        reply_markup ={
        "inline_keyboard":[
        [
        {"text":"Trinh sat nguoc OSINT","callback_data":f"recon:{ip }"},
        {"text":"Dua vao Tarpit","callback_data":f"tarpit:{ip }"},
        ],
        [
        {"text":"Chan Firewall tuc thi","callback_data":f"block:{ip }"},
        {"text":"Mo khoa IP","callback_data":f"unblock:{ip }"},
        ],
        ]
        }


        text_html =(
        f"<b>[CANH BAO AN NINH SOAR - MINI SOC]</b>\n"
        f"------------------------------------\n"
        f"<b>Su kien:</b> {html .escape (str (rule_name ))}\n"
        f"<b>Muc do:</b> <code>{html .escape (str (severity ))}</code>\n"
        f"<b>Ke tan cong (IP):</b> <code>{html .escape (str (ip ))}</code>\n"
        f"<b>Ky thuat MITRE:</b> <code>{html .escape (str (mitre_id ))}</code> - {html .escape (str (mitre_name ))}\n"
        f"<b>Thoi gian:</b> <code>{html .escape (str (timestamp ))}</code>\n"
        f"------------------------------------\n"
        f"<b>Chi tiet:</b>\n"
        )
        for k ,v in details .items ():
            text_html +=f"- <i>{html .escape (str (k ))}:</i> <code>{html .escape (str (v ))}</code>\n"

        text_html +="\n<b>Chon hanh dong phan ung chu dong:</b>"


        text_plain =(
        f"[CANH BAO AN NINH SOAR - MINI SOC]\n"
        f"------------------------------------\n"
        f"Su kien: {rule_name }\n"
        f"Muc do: {severity }\n"
        f"Ke tan cong (IP): {ip }\n"
        f"Ky thuat MITRE: {mitre_id } - {mitre_name }\n"
        f"Thoi gian: {timestamp }\n"
        f"------------------------------------\n"
        f"Chi tiet:\n"
        )
        for k ,v in details .items ():
            text_plain +=f"- {k }: {v }\n"
        text_plain +="\nChon hanh dong phan ung chu dong:"


        payload ={
        "chat_id":self .chat_id ,
        "text":text_html ,
        "parse_mode":"HTML",
        "reply_markup":reply_markup ,
        }

        try :
            resp =requests .post (f"{self .base_url }/sendMessage",json =payload ,timeout =15 )
            if resp .status_code ==200 :
                return True
            else :
                print (f"[-] Telegram API HTML error ({resp .status_code }): {resp .text }")
        except Exception as e :
            print (f"[-] Loi ket noi Telegram khi gui HTML: {e }")


        try :
            fallback_payload ={
            "chat_id":self .chat_id ,
            "text":text_plain ,
            "reply_markup":reply_markup ,
            }
            resp_fallback =requests .post (f"{self .base_url }/sendMessage",json =fallback_payload ,timeout =15 )
            if resp_fallback .status_code ==200 :
                print ("[+] Gui tin nhan Telegram thanh cong qua che do du phong (Plain Text)!")
                return True
            else :
                print (f"[-] Telegram API fallback error ({resp_fallback .status_code }): {resp_fallback .text }")
        except Exception as e :
            print (f"[-] Loi ket noi Telegram fallback: {e }")

        return False

    def _print_simulation (self ,alert_data :Dict )->None :
        """In thông tin mô phỏng ra console khi chưa cấu hình Telegram."""
        print ("\n[TELEGRAM SOAR BOT SIMULATION]")
        print (f"TIEU DE: {alert_data .get ('rule_name')}")
        print (f"IP Muc tieu: {alert_data .get ('source_ip')}")
        print (f"MITRE ATT&CK: {alert_data .get ('mitre_id')} - {alert_data .get ('mitre_name')}")
        print (f"Hanh dong de xuat: {alert_data .get ('recommended_action')}")
        print ("[NUT BAM CO SAN]: [Quet nguoc OSINT] | [Chan IP ngay] | [Dua vao Tarpit]")
        if not self ._is_chat_id_valid ():
            print ("(Goi y: Mo bot tren Telegram va gui /start de bot tu dong nhan dien Chat ID cua ban!)\n")

    def send_simple_message (self ,message :str )->bool :
        """Gửi tin nhắn phản hồi văn bản đơn giản."""
        if not self ._is_token_valid ():
            print (f"[BOT PHAN HOI]: {message }")
            return True

        if not self ._is_chat_id_valid ():
            if not self ._auto_detect_chat_id ():
                print (f"[BOT PHAN HOI]: {message }")
                return True


        try :
            resp =requests .post (
            f"{self .base_url }/sendMessage",
            json ={"chat_id":self .chat_id ,"text":message ,"parse_mode":"HTML"},
            timeout =15 ,
            )
            if resp .status_code ==200 :
                return True
            else :
                print (f"[-] Telegram API simple msg error ({resp .status_code }): {resp .text }")
        except Exception as e :
            print (f"[-] Loi ket noi Telegram simple msg: {e }")


        try :

            clean_text =message .replace ("<b>","").replace ("</b>","").replace ("<code>","").replace ("</code>","")
            resp_fallback =requests .post (
            f"{self .base_url }/sendMessage",
            json ={"chat_id":self .chat_id ,"text":clean_text },
            timeout =15 ,
            )
            return resp_fallback .status_code ==200
        except Exception :
            return False

    def start_polling (self )->None :
        """Chạy luồng nền lắng nghe tương tác nút bấm từ người dùng Telegram."""
        if not self ._is_token_valid ():
            return

        self .is_running =True
        thread =threading .Thread (target =self ._poll_loop ,daemon =True )
        thread .start ()

    def _poll_loop (self )->None :
        while self .is_running :
            try :
                url =f"{self .base_url }/getUpdates?offset={self .last_update_id +1 }&timeout=10"
                resp =requests .get (url ,timeout =15 )
                if resp .status_code ==200 :
                    data =resp .json ()
                    for update in data .get ("result",[]):
                        self .last_update_id =update ["update_id"]


                        incoming_id =None
                        if "message"in update :
                            incoming_id =str (update ["message"].get ("chat",{}).get ("id",""))
                        elif "channel_post"in update :
                            incoming_id =str (update ["channel_post"].get ("chat",{}).get ("id",""))
                        elif "callback_query"in update :
                            incoming_id =str (update ["callback_query"].get ("message",{}).get ("chat",{}).get ("id",""))

                        if incoming_id and not self ._is_chat_id_valid ():
                            self .chat_id =incoming_id
                            print (f"\n[+] Tu dong nhan dien Chat ID Telegram: {incoming_id }")
                            self .send_simple_message ("<b>[SOAR] He thong Mini-SOC Active Defense & SOAR da ket noi thanh cong voi Telegram cua ban!</b>")

                        if "callback_query"in update :
                            self ._handle_callback (update ["callback_query"])
            except Exception :
                time .sleep (3 )

    def _handle_callback (self ,query :Dict )->None :
        """Xử lý khi chuyên viên SOC bấm vào các nút hành động."""
        query_id =query .get ("id")
        data =query .get ("data","")

        try :
            requests .post (f"{self .base_url }/answerCallbackQuery",json ={"callback_query_id":query_id },timeout =10 )
        except Exception :
            pass

        if ":"not in data :
            return

        action ,ip =data .split (":",1 )
        if self .action_callback :
            result =self .action_callback (action ,ip )

            msg =(
            f"<b>[SOAR] HANH DONG DA THUC THI:</b> <code>{html .escape (action .upper ())}</code>\n"
            f"<b>Muc tieu:</b> <code>{html .escape (ip )}</code>\n"
            f"<b>Ket qua:</b> {html .escape (str (result .get ('action','Hoan tat')))}"
            )
            self .send_simple_message (msg )
