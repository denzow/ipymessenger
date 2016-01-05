#!/usr/bin/env python
# coding:utf-8

from __future__ import print_function, unicode_literals
import select
import socket
import threading
import lib.consts as c
from collections import deque
import time
import random
from lib.IpmsgMessage import IpmsgMessage, IpmsgMessageParser

"""
TODO
get host list
check message command info
"""

class IpmsgServer(threading.Thread):

    src_host = "0.0.0.0"

    def __init__(self, use_port):
        super(IpmsgServer, self).__init__()

        self.stop_event = threading.Event()
        self.use_port = use_port
        # initialize packet no
        rnd = random.Random()
        self.packet_no = rnd.randint(1, 100000)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # for broad cast
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind((self.src_host, self.use_port))
        self._entry()
        # for resrve sending
        self.send_que = deque()
        # TODO for check after sending
        self.sended_que = deque()

    def _entry(self):
        """
        join ipmsg network
        send BR_ENTRY
        """
        command = 0x0
        command |= c.IPMSG_BR_ENTRY
        # Ver(1) : Packet番号 : 自User名 : 自Host名 : Command番号 : 追加部
        send_msg = "1:%d:sayamada:B1308-66-01:%d:sayamada\00sayamada_group\00" % (self.get_packet_no(), command)
        print('Set Entry [%s]' % send_msg)
        # todo it's must be broadcast addr
        self.sock.sendto(send_msg.encode("utf-8"), ("255.255.255.255", self.use_port))
        # it is for test.
        # self.sock.sendto(send_msg.encode("utf-8"), (self.dest_host, self.use_port))


    def run(self):
        """
        main function
        :return:
        """
        print("Start listen.")
        while not self.stop_event.is_set():
            r, w, e = select.select([self.sock], [self.sock], [], 0)
            time.sleep(1)
            # print((r, w, e))
            # recive message
            for sk in r:
                data, (ip, port) = sk.recvfrom(c.UDP_DATA_LEN)
                # parse message
                # todo check encoding
                ip_msg = IpmsgMessageParser(ip, port, data.decode("utf-8", "ignore"))
                # action for command
                result = self.dispatch_action(ip_msg)


            # send message
            if w and self.send_que:
                while self.send_que:
                    send_msg = self.send_que.pop()
                    print("To[%s:%s]" % (send_msg.addr, send_msg.port))
                    print(send_msg.get_full_message())
                    self.sock.sendto(send_msg.get_full_message(), (send_msg.addr, send_msg.port))

        # close socket before ipmsg thread end
        self.sock.close()
        print("closed socket")

    def stop(self):
        """
        stop ipmessenger thread
        :return:
        """
        self.stop_event.set()

    def send_message(self, to_addr, msg):
        """
        add send message to send_q
        :return:
        """
        # Ver(1) : Packet No : MyUserName : MyHostName : Command : Extra
        self.packet_no += 1
        # socket data must non unicode.
        ip_msg = IpmsgMessage(to_addr, self.use_port, msg.encode("utf-8"), self.get_packet_no(), "sayamada")
        ip_msg.set_sendmsg()
        print(ip_msg.is_sendmsg())
        print(ip_msg.is_sendcheckopt())

        self.send_que.append(ip_msg)

    def get_packet_no(self):
        """
        get packet no
        """
        self.packet_no += 1
        return self.packet_no


    def dispatch_action(self, ip_msg):
        print("from[%s:%s]is rcvmsg?[%s]" % (ip_msg.addr, ip_msg.port, ip_msg.is_recvmsg()))

        if ip_msg.is_recvmsg():
            return self.recvmsg_action(ip_msg)

        else:
            return self.default_action(ip_msg)

    def default_action(self, msg):
        print(msg)

    def recvmsg_action(self, msg):
        print("recvmsg:" + msg.get_full_message())