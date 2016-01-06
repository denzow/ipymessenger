#!/usr/bin/env python
# coding:utf-8
from __future__ import print_function, unicode_literals
import time
from lib.IpmsgServer import IpmsgServer


if __name__ == "__main__":

    dest_host = "192.168.26.189"
    ip = IpmsgServer("sayamada", "ymsft_group", 2721)
    try:
        ip.start()
        """
        hello_no = ip.send_message(dest_host, "hello")
        hello2_no = ip.send_message(dest_host, "hello2")
        # 10s wait
        time.sleep(10)
        print("hello is success:" + str(ip.check_sended_message(hello_no)))
        print("hello2 is success:" + str(ip.check_sended_message(hello2_no)))
        """
        time.sleep(10)
        print(ip.get_hostinfo_by_nickname("denzow"))
        print(ip.get_hostinfo_by_nickname("slope"))
        print(ip.get_hostinfo_by_nickname("no user"))


        time.sleep(100)

    except Exception as e:
        print("Exception occured")
        print(e)
    finally:
        ip.stop()
        ip.join()
