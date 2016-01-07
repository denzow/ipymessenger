#!/usr/bin/env python
# coding:utf-8

from __future__ import print_function, unicode_literals
import select
import socket
import threading
import sys
import traceback
from lib.consts import command_const as c
from collections import deque
import time
import random
import datetime
from lib.IpmsgMessage import IpmsgMessage, IpmsgMessageParser
from lib.IpmsgHostinfo import IpmsgHostinfo, IpmsgHostinfoListParser, IpmsgHostinfoParser
import lib.common as com


class IpmsgServer(threading.Thread):

    src_host = "0.0.0.0"
    # TODO
    sended_que_life_time = 30

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
        # main loop
        try:
            while not self.stop_event.is_set():
                r, w, e = select.select([self.sock], [self.sock], [], 0)
                time.sleep(0.1)
                # print((r, w, e))
                # recive message
                for sk in r:
                    data, (ip, port) = sk.recvfrom(0x80000)
                    # parse message
                    ip_msg = IpmsgMessageParser(ip, port, com.to_unicode(data))
                    # action for command
                    self.dispatch_action(ip_msg)

                # send message
                if w and self.send_que:
                    # send message loop until que empty.
                    while self.send_que:
                        # FIFO
                        send_msg = self.send_que.popleft()
                        print("To[%s:%s]" % (send_msg.addr, send_msg.port))
                        [print("\t"+x) for x in send_msg.check_flag()]
                        print(send_msg.get_full_message())
                        self.sock.sendto(send_msg.get_full_message(), (send_msg.addr, send_msg.port))

                        if send_msg.is_sendmsg():
                            # for check sendmsg success
                            # if long time in the sended que, the message must be failed.
                            send_msg.born_time = datetime.datetime.now()
                            self.sended_que.append(send_msg)

                self._cleanup_ques()
        except Exception as e:
            error_args = sys.exc_info()
            print(traceback.print_tb(error_args[2]))
            print(e)

        # close socket before ipmsg thread end
        self.sock.close()
        self.sock = None
        print("closed socket")

    #########################
    # PUBLIC METHOD
    #########################
    def is_valid(self):
        """
        server is running.
        :return:
        """
        return not (self.sock is None)


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
        ip_msg = IpmsgMessage(to_addr, self.use_port, msg, packet_no, self.user_name)
        ip_msg.set_sendmsg()
        self._send(ip_msg)

        # for follow send status. so return packet no.
        return packet_no

    def check_sended_message(self, packet_no):
        """
        if the packet no is in sended_que and send_que, the message is not success yet.
        :param packet_no:
        :return:
        """
        return not ((packet_no in [x.packet_no for x in self.sended_que]) or (packet_no in [x.packet_no for x in self.send_que]))

    def send_message_by_nickname(self, nickname, msg):
        """
        search addr by nickname
        and
        add send message to send_q
        :return: packet no because check send success or fail.
        """
        # Ver(1) : Packet No : MyUserName : MyHostName : Command : Extra

        host_info = self.get_hostinfo_by_nickname(nickname)

        if host_info:
            packet_no = self._get_packet_no()
            ip_msg = IpmsgMessage(host_info.addr, self.use_port, msg, packet_no, self.user_name)
            ip_msg.set_sendmsg()
            self._send(ip_msg)
            # for follow send status. so return packet no.
            return packet_no
        else:
            raise IpmsgException("nickname matched host is not found.")

    def send_message_by_fuzzy_nickname(self, nickname, msg):
        """
        search addr by nickname
        if nickname's not exist, try to fuzzy search.
        and
        add send message to send_q
        :return: packet no because check send success or fail.
        """
        # Ver(1) : Packet No : MyUserName : MyHostName : Command : Extra
        # rule list
        # (func, name + args)
        try_rule_list = [
            (lambda x: x, [nickname]),  # 1st do nothing
            (com.adjust_name, [nickname, ""]),
            (com.adjust_name, [nickname, " "]),  # single space
            (com.adjust_name, [nickname, "  "]),  # double single space
            (com.adjust_name, [nickname, "　"]),  # multi byte space
        ]
        host_info = None
        for rule_func, rule_arg in try_rule_list:
            print(rule_func(*rule_arg))
            host_info = self.get_hostinfo_by_nickname(rule_func(*rule_arg))
            if host_info:
                break

        if host_info:
            packet_no = self._get_packet_no()
            ip_msg = IpmsgMessage(host_info.addr, self.use_port, msg, packet_no, self.user_name)
            ip_msg.set_sendmsg()
            self._send(ip_msg)
            # for follow send status. so return packet no.
            return packet_no
        else:
            raise IpmsgException("nickname fuzzy matched host is not found.")

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

        # br_entry's ans entry must be ignore.
        # another client to  i'm online too.
        if ip_msg.is_br_entry() and not ip_msg.is_ansentry():
            self.br_entry_action(ip_msg)

        # okgetlist message have getlist flag too.
        # so if both flag set, ignore.
        # avoid loop getlist <-> okgetlist
        if ip_msg.is_okgetlist() and not ip_msg.is_getlist():
            self.okgetlist_action(ip_msg)

        # receive message from other host sended.
        if ip_msg.is_sendmsg():
            self.sendmsg_action(ip_msg)

        self.default_action(ip_msg)

        # if recv message any host, should be register host.
        self._add_host_list(IpmsgHostinfoParser(ip_msg))

    def default_action(self, msg):
        """
        mock action.
        :param msg:
        :return:
        """
        print("default:" + msg.get_full_unicode_message().__repr__())

    def recvmsg_action(self, msg):
        """
        Send message use IPMSG_SENDMSG. if IPMSG_SENDCHECKOPT,
        receiver return  IPMSG_RECVMSG and same packet_no.

        this case , check sended que and remove target_msg,
        because the message is success sending.
        """
        print("recvmsg:" + msg.get_full_unicode_message())
        for s_msg in self.sended_que:

            # packet_no is not endwith \00
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
        begin_no, host_count, host_list = IpmsgHostinfoListParser(msg.get_full_unicode_message())
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
        send_msg = "%s\00%s" % (self.user_name, self.group_name)
        ip_msg = IpmsgMessage(msg.addr, msg.port, send_msg, self._get_packet_no(), self.user_name)
        ip_msg.set_flag(c.IPMSG_ANSENTRY)
        print("br_entry_re:" + ip_msg.get_full_message().__repr__())
        self._send(ip_msg)

    def sendmsg_action(self, msg):
        """
        recv message action
        :param msg:
        :return:
        """
        print("sendmsg:" + msg.get_full_unicode_message())
        if msg.is_sendcheckopt():
            ip_msg = IpmsgMessage(msg.addr, msg.port, msg.packet_no, self._get_packet_no(), self.user_name)
            ip_msg.set_flag(c.IPMSG_RECVMSG)
            self._send(ip_msg)

    ####################
    # INTERNAL METHOD
    #####################

    def _entry(self):
        """
        join ipmsg network
        send BR_ENTRY
        """
        # Ver : PacketNo : User : Host : Command : Msg
        #send_msg = "1:%s:sayamada:B1308-66-01:%d:sayamada\00sayamada_group\00" % (self.get_packet_no(), command)
        send_msg = "%s\00%s" % (self.user_name, self.group_name)

        ip_msg = IpmsgMessage("255.255.255.255", self.use_port, send_msg, self._get_packet_no(), self.user_name)
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
        # msg is not int. so packet_no must be str too.
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

    def _cleanup_ques(self):

        now = datetime.datetime.now()
        aged_out_list = [msg for msg in self.sended_que if (now - msg.born_time) > datetime.timedelta(seconds=self.sended_que_life_time)]
        for msg in aged_out_list:
            print("Age out:[%s:%s]" % (msg.packet_no, msg.addr))
            self.sended_que.remove(msg)


class IpmsgException(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return repr(self.message)
