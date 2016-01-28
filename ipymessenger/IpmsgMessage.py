#!/usr/bin/env python
# coding:utf-8
from __future__ import print_function, unicode_literals
from socket import gethostname
import datetime
from ipymessenger.consts import command_const as c


class IpmsgMessage(object):

    def __init__(self, addr, port, message, packet_no, username, hostname=None, command=None):
        self.addr = addr
        self.port = port
        # message must be end with \00
        self.message = message.rstrip("\00")+"\00"
        # : is special character for ipmsg protocol so replace.
        self.message = self.message.replace(":",";")

        self.packet_no = packet_no
        self.username = username
        self.command = 0x0
        if command:
            self.command = command
        self.hostname = gethostname()
        if hostname:
            self.hostname = hostname

        # TODO
        self.encode = "sjis"
        self.sub_encode = "cp932"
        # for manage limit dead
        self.born_time = None

    def get_full_message(self):
        # Ver(1) : Packet No : MyUserName : MyHostName : Command : msg

        ret_msg = "1:%s:%s:%s:%s:%s" % (
            self.packet_no,
            self.username,
            self.hostname,
            self.command,
            self.message
        )
        try:
            return ret_msg.encode(self.encode)
        except UnicodeEncodeError:
            return ret_msg.encode(self.sub_encode)

    def get_full_unicode_message(self):
        # Ver(1) : Packet No : MyUserName : MyHostName : Command : msg

        ret_msg = "1:%s:%s:%s:%s:%s" % (
            self.packet_no,
            self.username,
            self.hostname,
            self.command,
            self.message
        )
        return ret_msg

    def set_flag(self, flag):
        self.command |= flag

    def set_sendmsg(self):
        """
        this message is sendmessage
        :return:
        """
        #self.command = 8405280
        self.set_flag(c.IPMSG_SENDCHECKOPT)
        self.set_flag(c.IPMSG_SENDMSG)

    def set_secretopt(self):
        """
        this message is sendmessage
        :return:
        """
        #self.command = 8405280
        self.set_flag(c.IPMSG_SECRETOPT)

    def set_ansentry(self):
        self.set_flag(c.IPMSG_ANSENTRY)

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

    def is_ansentry(self):
        return self.is_type(c.IPMSG_ANSENTRY)

    def is_okgetlist(self):
        return self.is_type(c.IPMSG_OKGETLIST)

    def is_getlist(self):
        return self.is_type(c.IPMSG_GETLIST)

    def is_br_entry(self):
        return self.is_type(c.IPMSG_BR_ENTRY)

    def is_br_exit(self):
        return self.is_type(c.IPMSG_BR_EXIT)

    def is_secretopt(self):
        return self.is_type(c.IPMSG_SECRETOPT)

    def is_readmsg(self):
        return self.is_type(c.IPMSG_READMSG)


    def check_flag(self):
        """
        main reason. for debug.
        :return:
        """
        ret = []
        ci = c()
        consts = [ x for x in dir(ci) if "__" not in x]
        for const in consts:
            if self.is_type(ci.__getattribute__(const)):
                ret.append(const)

        return ret

    def born_now(self):
        """
        メッセージに誕生日を付与する
        :return:
        """
        self.born_time = datetime.datetime.now()

    def __repr__(self):
        return self.get_full_message()

    def __unicode__(self):
        return self.get_full_unicode_message()

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

    return IpmsgMessage(
        addr,
        port,
        message,
        packet_no,
        username,
        hostname,
        command
    )


