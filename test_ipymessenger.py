#!/usr/bin/env python
# coding:utf-8
from __future__ import print_function, unicode_literals

import sys
import time
import traceback
from logging import StreamHandler
from ipymessenger.IpmsgServer import IpmsgServer

if __name__ == "__main__":

    dest_host = "192.168.26.189"
    # デバッグメッセージが必要な場合はloggingのHandlerを渡す
    #ip = IpmsgServer("sayamada", "ymsft_group", 2722, StreamHandler(), broad_cast_addrs=["172.16.25.0"])
    ip = IpmsgServer("sayamada", "ymsft_group", 2722, StreamHandler(), broad_cast_addrs=["172.16.25.0"], request_info_interval=20)
    #ip.set_sendmsg_handler(lambda x: x.message.rstrip("\00")+"ADD BY HANDLER")
    #ip = IpmsgServer("sayamada", "ymsft_group", 2722)
    try:
        #ip.set_sendmsg_handler(lambda x:print(x))
        ip.start()
        time.sleep(60)

        """
        hello_no = ip.send_message(dest_host, "⑫", is_secret=True)
        time.sleep(3)
        print("######hello send success:" + str(ip.check_sended_message(hello_no)))
        print("######hello is_read?:" + str(ip.check_readed_message(hello_no)))
        time.sleep(5)
        print("######hello is_read?:" + str(ip.check_readed_message(hello_no)))
        for x in ip.host_list_dict:
            print(x, ip.host_list_dict[x].group)

        test_no = ip.send_message_by_fuzzy_nickname("slope  太郎", "へろー by name", is_secret=True)
        time.sleep(5)
        print("######test_no is success:" + str(ip.check_sended_message(test_no)))

        test_no = ip.send_message_by_osusername("Administrator", "へろー by name", is_secret=True)
        time.sleep(5)
        print("######test_no is success:" + str(ip.check_sended_message(test_no)))

        print(ip.sended_que)
        #test_no = ip.send_message_by_osusername("Administrator", "へろー by name")
        #time.sleep(5)
        #print("######test_no is success:" + str(ip.check_sended_message(test_no)))
        #print(ip.get_message("192.168.26.189"))
        #time.sleep(10)
        #print(ip.get_message("192.168.26.189"))

        print("#"*20)
        for x in ip.host_list_dict:
            print(1,x)
            print(2,ip.host_list_dict[x].addr)
            print(3,ip.host_list_dict[x].user_name)
        """


        time.sleep(100)

    except Exception as e:
        print("Exception occured")

        error_args = sys.exc_info()
        print(traceback.print_tb(error_args[2]))
        print(e)

    finally:
        ip.stop()
        ip.join()
