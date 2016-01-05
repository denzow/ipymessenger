#!/usr/bin/env python
# coding:utf-8
from __future__ import print_function, unicode_literals
from socket import gethostname
import lib.consts as c


class IpmsgMessage(object):

    def __init__(self, addr, port, message, packet_no, username, hostname=None, command=None):
        self.addr = addr
        self.port = port
        self.message = message
        self.packet_no = packet_no
        self.username = username
        self.command = 0x0
        if command:
            self.command = command
        self.hostname = gethostname()
        if hostname:
            self.hostname = hostname

    def get_full_message(self):
        # Ver(1) : Packet No : MyUserName : MyHostName : Command : msg
        ret_msg = "1:%s:%s:%s:%s:%s" % (
            self.packet_no,
            self.username,
            self.hostname,
            self.command,
            self.message
        )

        return ret_msg

    def set_sendmsg(self):
        """
        this message is sendmessage
        :return:
        """
        self.command = 8405280

    def is_type(self, flag):
        """
        check packet type
        :param flag: IPMSG_XXXX
        :return: is message's command flaged?
        """
        return (int(self.command) & flag) == flag

    def is_sendmsg(self):
        return self.is_type(c.IPMSG_SENDMSG)

    def is_sendcheckopt(self):
        return self.is_type(c.IPMSG_SENDCHECKOPT)

    def is_recvmsg(self):
        return self.is_type(c.IPMSG_RECVMSG)


    def __repr__(self):
        return self.get_full_message()

    def __unicode__(self):
        return self.get_full_message()

    def __str__(self):
        return self.get_full_message()


def IpmsgMessageParser(addr, port, msg_str):
    """
    parse msg str to IpmsgMessage instance.
    :param from_addr:
    :param from_port:
    :param msg_str:
    :return: IpmsgMessanger instance
    """
    attr_list = msg_str.split(":")
    # Ver(1) : Packet No : MyUserName : MyHostName : Command : msg
    ver = attr_list[0]
    packet_no = attr_list[1]
    username = attr_list[2]
    hostname = attr_list[3]
    command = attr_list[4]
    message = attr_list[5]
    print(attr_list)

    return IpmsgMessage(
        addr,
        port,
        message,
        int(packet_no),
        username,
        hostname,
        command
    )


