#!/usr/bin/env python
# coding:utf-8

import socket

host = '127.0.0.1'
port = 3794
serversock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

send_msg = "1:505822338:sayamada:B1308-66-01:8405280:こんにちは"
print 'Send message...[%s]' % send_msg
serversock.sendto(send_msg, (host, port))