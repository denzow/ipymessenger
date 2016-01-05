#!/usr/bin/env python
# coding:utf-8
from __future__ import print_function, unicode_literals


import time
from lib.IpmsgServer import IpmsgServer


if __name__ == "__main__":

    dest_host = "192.168.26.189"
    ip = IpmsgServer(2722)
    try:
        ip.start()
        ip.send_message(dest_host, "hello")
        ip.send_message(dest_host, "hello2")
        # 10s wait
        time.sleep(100)
    except Exception as e:
        print("Exception occured")
        print(e)
    finally:
        ip.stop()
        ip.join()
