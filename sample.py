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

        hello_no = ip.send_message(dest_host, "へろー")
        fail_msg_no = ip.send_message("192.168.26.193", "へろー")
        ip.send_message("192.168.26.193", "へろー")
        ip.send_message("192.168.26.193", "へろー")
        ip.send_message("192.168.26.193", "へろー")

        #hello2_no = ip.send_message(dest_host, "hello2")
        # 10s wait
        #time.sleep(5)

        print("######hello is success:" + str(ip.check_sended_message(hello_no)))
        print("######fail_msg_no is success:" + str(ip.check_sended_message(fail_msg_no)))
        # print("hello2 is success:" + str(ip.check_sended_message(hello2_no)))

        time.sleep(5)

        print("######hello is success:" + str(ip.check_sended_message(hello_no)))
        print("######fail_msg_no is success:" + str(ip.check_sended_message(fail_msg_no)))
        print(ip.sended_que)

        time.sleep(100)


    except Exception as e:
        print("Exception occured")

        errorArgs = sys.exc_info()
        print(traceback.print_tb(errorArgs[2]))
        print(e)

    finally:
        ip.stop()
        ip.join()
