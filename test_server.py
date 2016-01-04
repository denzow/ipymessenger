#!/usr/bin/env python
# coding:utf-8

import socket
import select
import time

host = '127.0.0.1'
port = 3794
clientsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
clientsock.bind((host, port))
print "wait..."
while True:
    r, w, e = select.select([clientsock], [clientsock], [], 0)
    print r, w, e
    time.sleep(0.5)
"""
while True:
  recv_msg, addr = clientsock.recvfrom(1024)
  print "Received ->", recv_msg
"""
