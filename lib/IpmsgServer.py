#!/usr/bin/env python
# coding:utf-8

from __future__ import print_function, unicode_literals
import select
import socket
import threading
from lib.consts import command_const as c
from collections import deque
import time
import random
import datetime
from lib.IpmsgMessage import IpmsgMessage, IpmsgMessageParser

"""
TODO
get host list
check message command info
"""

class IpmsgServer(threading.Thread):

    src_host = "0.0.0.0"

    def __init__(self, user_name, group_name, use_port):
        """

        :param user_name: for send message and hostlist
        :param group_name: for hostlist
        :param use_port: listening port
        :return:
        """
        super(IpmsgServer, self).__init__()

        self.stop_event = threading.Event()
        self.use_port = use_port
        self.user_name = user_name
        self.group_name = group_name

        # initialize packet no
        rnd = random.Random()
        self.packet_no = rnd.randint(1, 100000)
        # create socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # for broad cast
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind((self.src_host, self.use_port))

        # for resrve sending
        self.send_que = deque()
        # for check send success
        self.sended_que = deque()

        # initialize hostlist
        # ユーザ名:ホスト名:コマンド番号:IP アドレス:ポート番号（リトルエンディアン）:ニックネーム:グループ名
        self.host_list = {}

        # say hello
        self._entry()
        # self._get_host_list()


    def _entry(self):
        """
        join ipmsg network
        send BR_ENTRY
        """
        # Ver(1) : Packet番号 : 自User名 : 自Host名 : Command番号 : 追加部
        #send_msg = "1:%s:sayamada:B1308-66-01:%d:sayamada\00sayamada_group\00" % (self.get_packet_no(), command)
        send_msg = "%s\00%s\00" % (self.user_name, self.group_name)

        ip_msg = IpmsgMessage("255.255.255.255", self.use_port, send_msg.encode("utf-8"), self.get_packet_no(), self.user_name)
        ip_msg.set_flag(c.IPMSG_BR_ENTRY)
        # todo it's must be broadcast addr
        self._send(ip_msg)
        #self.sock.sendto(send_msg.encode("utf-8"), ("255.255.255.255", self.use_port))
        # it is for test.
        # self.sock.sendto(send_msg.encode("utf-8"), (self.dest_host, self.use_port))

    def _get_host_list(self):
        #1:801798212:root:falcon:6291480:(\00)
        ip_msg = IpmsgMessage("255.255.255.255", self.use_port, "", self.get_packet_no(), self.user_name)
        ip_msg.set_flag(c.IPMSG_BR_ISGETLIST2)
        self._send(ip_msg)



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
                data, (ip, port) = sk.recvfrom(0x80000)
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

                    # for check send success
                    send_msg.born_time = datetime.datetime.now()
                    self.sended_que.append(send_msg)


        # close socket before ipmsg thread end
        self.sock.close()
        print("closed socket")

    def stop(self):
        """
        stop ipmessenger thread
        :return:
        """
        self.stop_event.set()

    def _send(self, ip_msg):
        self.send_que.append(ip_msg)


    def send_message(self, to_addr, msg):
        """
        add send message to send_q
        :return: packet no because check send success or fail.
        """
        # Ver(1) : Packet No : MyUserName : MyHostName : Command : Extra
        packet_no = self.get_packet_no()
        # socket data must non unicode.
        ip_msg = IpmsgMessage(to_addr, self.use_port, msg.encode("utf-8"), packet_no, self.user_name)
        ip_msg.set_sendmsg()
        self._send(ip_msg)


        return packet_no

    def check_sended_message(self, packet_no):
        """
        if the packet no is in sended_que, the message is not success yet.
        :param packet_no:
        :return:
        """
        return not (packet_no in [x.packet_no for x in self.sended_que])

    def get_packet_no(self):
        """
        get packet no
        """
        self.packet_no += 1
        # msg is not int. must be str
        return unicode(self.packet_no)

    def dispatch_action(self, ip_msg):
        """
        dispatch action by
        :param ip_msg:
        :return:
        """
        print("from[%s:%s]" % (ip_msg.addr, ip_msg.port))
        [print(x) for x in ip_msg.check_flag()]

        if ip_msg.is_recvmsg():
            self.recvmsg_action(ip_msg)

        if ip_msg.is_ansentry():
            self.ansentry_action(ip_msg)

        if ip_msg.is_getlist():
            self.getlist_action(ip_msg)

        if ip_msg.is_okgetlist():
            self.okgetlist_action(ip_msg)

        else:
            self.default_action(ip_msg)

    def default_action(self, msg):
        """
        mock action.
        :param msg:
        :return:
        """
        print("default:" + msg.get_full_message())

    def recvmsg_action(self, msg):
        """
        メッセージ送信には IPMSG_SENDMSG を使用し、拡張部にメッセージ本体
        を入れます。受信側は、IPMSG_SENDCHECKOPT が立っている場合に限り、
        IPMSG_RECVMSG を返します。拡張部には元のパケット番号を入れます。
        """
        print("recvmsg:" + msg.get_full_message())
        for s_msg in self.sended_que:

            if s_msg.packet_no == msg.message.rstrip("\00"):
                print("send success:" + s_msg.get_full_message())
                self.sended_que.remove(s_msg)
                break

    def ansentry_action(self, msg):
        """
        ansentry is response for brentry

        :param msg:
        :return:
        """
        # TODO
        # add hostlist
        print("ansentry:" + msg.get_full_message().__repr__())


    def okgetlist_action(self, msg):
        """
        recv okgetlist, send to getlist packet.

        :param msg:
        :return:
        """
        # TODO
        # add hostlist
        print("okgetlist:" + msg.get_full_message())
        # "1:100:sender:sender-pc:18:0"

        ip_msg = IpmsgMessage(msg.addr, msg.port, "", self.get_packet_no(), self.user_name)
        ip_msg.set_flag(c.IPMSG_GETLIST)
        self._send(ip_msg)

    def getlist_action(self, msg):
        print("getlist:" + msg.get_full_message().__repr__())
