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
from lib.IpmsgHostinfo import IpmsgHostinfo, IpmsgHostinfoListParser, IpmsgHostinfoParser

"""
TODO
get host list
check message command info
"""

class IpmsgServer(threading.Thread):

    src_host = "0.0.0.0"

    def __init__(self, user_name, group_name, use_port=2524):
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
        # {
        #   denzow: HostInfo(osuser:B1308-66-01:0:192.168.24.97:41482:denzow:ymsft_group),
        #   :
        # }
        self.host_list_dict = {}

        # say hello
        self._entry()
        # please hostlist
        self._request_host_list()


    def run(self):
        """
        main function
        :return:
        """
        print("Start listen.")
        while not self.stop_event.is_set():
            r, w, e = select.select([self.sock], [self.sock], [], 0)
            time.sleep(0.1)
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

    #########################
    # PUBLIC METHOD
    #########################
    def stop(self):
        """
        stop ipmessenger thread
        :return:
        """
        self.stop_event.set()

    def send_message(self, to_addr, msg):
        """
        add send message to send_q
        :return: packet no because check send success or fail.
        """
        # Ver(1) : Packet No : MyUserName : MyHostName : Command : Extra
        packet_no = self._get_packet_no()
        # socket data must non unicode.
        ip_msg = IpmsgMessage(to_addr, self.use_port, msg.encode("utf-8"), packet_no, self.user_name)
        ip_msg.set_sendmsg()
        self._send(ip_msg)

        # for follow send status. so return packet no.
        return packet_no

    def check_sended_message(self, packet_no):
        """
        if the packet no is in sended_que, the message is not success yet.
        :param packet_no:
        :return:
        """
        return not (packet_no in [x.packet_no for x in self.sended_que])

    def get_hostinfo_by_nickname(self, nickname):
        """
        if the nick_name's info is not exist, return None.
        :param nickname:
        :return:
        """
        return self.host_list_dict.get(nickname, None)

    #########################
    # ACTION LIST
    #########################
    def dispatch_action(self, ip_msg):
        """
        dispatch action by
        :param ip_msg:
        :return:
        """
        print("from[%s:%s]" % (ip_msg.addr, ip_msg.port))
        # TODO debug
        [print("\t"+x) for x in ip_msg.check_flag()]

        # TODO consider duplicate flag action
        if ip_msg.is_recvmsg():
            self.recvmsg_action(ip_msg)

        if ip_msg.is_ansentry():
            self.ansentry_action(ip_msg)

        if ip_msg.is_getlist():
            self.getlist_action(ip_msg)

        # br_entry's ans entry must be ignore.9
        # another client to  i'm online too.
        if ip_msg.is_br_entry() and not ip_msg.is_ansentry():
            self.br_entry_action(ip_msg)

        # okgetlist message have getlist flag too.
        # so if both flag set, ignore.
        # avoid loop getlist <-> okgetlist
        if ip_msg.is_okgetlist() and not ip_msg.is_getlist():
            self.okgetlist_action(ip_msg)

        else:
            self.default_action(ip_msg)

        # if recv message any host, should be register host.
        self._add_host_list(IpmsgHostinfoParser(ip_msg))

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
                # print("send success:" + s_msg.get_full_message())
                self.sended_que.remove(s_msg)
                break

    def ansentry_action(self, msg):
        """
        ansentry is response for brentry
        add host_list

        :param msg:
        :return:
        """
        pass
        #print("ansentry:" + msg.get_full_message().__repr__())

    def okgetlist_action(self, msg):
        """
        recv okgetlist, send to getlist packet.

        :param msg:
        :return:
        """
        # add hostlist
        #print("okgetlist:" + msg.get_full_message())
        # "1:100:sender:sender-pc:18:0"

        ip_msg = IpmsgMessage(msg.addr, msg.port, "", self._get_packet_no(), self.user_name)
        ip_msg.set_flag(c.IPMSG_GETLIST)
        self._send(ip_msg)

    def getlist_action(self, msg):
        """
        when get hostlist then register self.host_list_dict
        host_list key is nick_name.

        :param msg:
        :return:
        """
        #print("getlist:" + msg.get_full_message().__repr__())
        print("getlist")
        begin_no, host_count, host_list = IpmsgHostinfoListParser(msg.get_full_message())
        for host in host_list:
            self._add_host_list(host)

    def br_entry_action(self, msg):
        """
        if recv br_entry, must be send ansentry.
        and add host_list
        # 1:1452074470:Administrator-<848363a9d00e6944>:YAMADROID2003:224399361:YAMADROID2003\x00\x00\nUN\x00
        :param msg:
        :return:
        """
        print("br_entry:" + msg.get_full_message().__repr__())
        ip_msg = IpmsgMessage(msg.addr, msg.port, "", self._get_packet_no(), self.user_name)
        ip_msg.set_flag(c.IPMSG_ANSENTRY)
        self._send(ip_msg)


    ####################
    # INTERNAL METHOD
    #####################

    def _entry(self):
        """
        join ipmsg network
        send BR_ENTRY
        """
        # Ver(1) : Packet番号 : 自User名 : 自Host名 : Command番号 : 追加部
        #send_msg = "1:%s:sayamada:B1308-66-01:%d:sayamada\00sayamada_group\00" % (self.get_packet_no(), command)
        send_msg = "%s\00%s\00" % (self.user_name, self.group_name)

        ip_msg = IpmsgMessage("255.255.255.255", self.use_port, send_msg.encode("utf-8"), self._get_packet_no(), self.user_name)
        ip_msg.set_flag(c.IPMSG_BR_ENTRY)
        # todo it's must be broadcast addr
        self._send(ip_msg)
        #self.sock.sendto(send_msg.encode("utf-8"), ("255.255.255.255", self.use_port))
        # it is for test.
        # self.sock.sendto(send_msg.encode("utf-8"), (self.dest_host, self.use_port))

    def _request_host_list(self):
        #1:801798212:root:falcon:6291480:(\00)
        ip_msg = IpmsgMessage("255.255.255.255", self.use_port, "", self._get_packet_no(), self.user_name)
        ip_msg.set_flag(c.IPMSG_BR_ISGETLIST2)
        self._send(ip_msg)

    def _get_packet_no(self):
        """
        get packet no
        """
        self.packet_no += 1
        # msg is not int. must be str
        return unicode(self.packet_no)

    def _send(self, ip_msg):
        self.send_que.append(ip_msg)

    def _add_host_list(self, host_info):
        """
        append host info
        nick_name must be uniq.
        :param host_info:
        :return:
        """
        self.host_list_dict[host_info.nick_name] = host_info
