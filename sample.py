#!/usr/bin/env python
# coding:utf-8
from __future__ import print_function, unicode_literals
import time
import sys
import traceback
from lib.IpmsgServer import IpmsgServer


if __name__ == "__main__":

    dest_host = "192.168.26.189"
    ip = IpmsgServer("sayamada", "ymsft_group", 2722)
    try:
        ip.start()
        time.sleep(10)
        hello_no = ip.send_message(dest_host, "へろー")
        time.sleep(5)

        print("######hello is success:" + str(ip.check_sended_message(hello_no)))
        """
        test_no = ip.send_message_by_nickname("slope", "へろー by name")


        #hello2_no = ip.send_message(dest_host, "hello2")
        # 10s wait
        #time.sleep(5)

        print("######hello is success:" + str(ip.check_sended_message(hello_no)))
        print("test_no is success:" + str(ip.check_sended_message(test_no)))

        time.sleep(5)

        print("######hello is success:" + str(ip.check_sended_message(hello_no)))
        print("test_no is success:" + str(ip.check_sended_message(test_no)))
        print(ip.sended_que)
        """
        #ip.send_message_by_fuzzy_nickname("slope 太郎", "へろー")
        time.sleep(100)


    except Exception as e:
        print("Exception occured")

        error_args = sys.exc_info()
        print(traceback.print_tb(error_args[2]))
        print(e)

    finally:
        ip.stop()
        ip.join()
