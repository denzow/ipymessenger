#!/usr/bin/env python
# coding:utf-8
from __future__ import print_function, unicode_literals
from ipymessenger.consts import command_const as c

class IpmsgHostinfo(object):

    def __init__(self, user_name, host_name, command, addr, port, nick_name, group):
        # user1:host1:65536:192.168.0.0:30985:NickName1:Group1:
        # os_username:hostname:command:ipaddr:port:
        self.user_name = user_name
        self.host_name = host_name
        self.command = command
        self.addr = addr
        self.port = port
        self.nick_name = nick_name
        self.group = group

    def __str__(self):
        return ("IpmsgHostinfo:%s:%s:%s:%s:%s:%s:%s" % (
            self.user_name,
            self.host_name,
            self.command,
            self.addr,
            self.port,
            self.nick_name,
            self.group
        )).encode("utf-8")

    def __unicode__(self):
        return "IpmsgHostinfo:%s:%s:%s:%s:%s:%s:%s" % (
            self.user_name,
            self.host_name,
            self.command,
            self.addr,
            self.port,
            self.nick_name,
            self.group
        )

    def __repr__(self):
        return ("IpmsgHostinfo:%s:%s:%s:%s:%s:%s:%s" % (
            self.user_name,
            self.host_name,
            self.command,
            self.addr,
            self.port,
            self.nick_name,
            self.group
        )).encode("utf-8")


def IpmsgHostinfoListParser(hostlist_str):
    """
    0\x07    2\x07
    Administrator-<327dac447c87a917>\x07SLOPE\x07232783872\x07192.168.26.189\x0741482\x07slope\x0722\x07
    denzow\x07B1308-66-01\x070\x07192.168.24.97\x0741482\x07denzow\x07ymsft_group\x07
    \x00
    """
    # print(hostlist_str.__repr__())
    host_list = []
    splited_host_list = hostlist_str.split("\07")
    begein_no = int(splited_host_list[0].strip())
    host_count = int(splited_host_list[1].strip())
    # ホストリスト毎に分割(7要素で1ペア)
    for x in zip(*[iter(splited_host_list[2:])]*7):
        host_list.append(IpmsgHostinfo(*x))

    return begein_no, host_count, host_list


def IpmsgHostinfoParser(normal_message_inst):
    #print("DEBUG", normal_message_inst, normal_message_inst.message.__repr__())
    #user_name, host_name, command, addr, port, nick_name, group):

    nick_name = None
    group_name = None
    splited_message = normal_message_inst.message.split("\00")
    if len(splited_message) > 1:
        nick_name = splited_message[0]
        group_name = splited_message[1]
    elif len(splited_message) == 1:
        nick_name = splited_message[0]



    info = IpmsgHostinfo(
        normal_message_inst.username,
        normal_message_inst.hostname,
        normal_message_inst.command,
        normal_message_inst.addr,
        normal_message_inst.port,
        nick_name,
        group_name
    )
    return info

if __name__ == "__main__":
    getlist_msg = "    0\x07    2\x07Administrator-<327dac447c87a917>\x07SLOPE\x07232783872\x07192.168.26.189\x0741482\x07slope\x0722\x07denzow\x07B1308-66-01\x070\x07192.168.24.97\x0741482\x07denzow\x07ymsft_group\x07\x00"
    IpmsgHostinfoParser(getlist_msg)


