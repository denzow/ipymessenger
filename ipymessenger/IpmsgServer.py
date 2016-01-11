#!/usr/bin/env python
# coding:utf-8

from __future__ import print_function, unicode_literals
import select
import socket
import threading
import sys
import traceback
from ipymessenger.consts import command_const as c
from collections import deque
import time
import random
import datetime
from ipymessenger.IpmsgMessage import IpmsgMessage, IpmsgMessageParser
from ipymessenger.IpmsgHostinfo import IpmsgHostinfo, IpmsgHostinfoListParser, IpmsgHostinfoParser
import ipymessenger.common as com
from logging import getLogger, StreamHandler, DEBUG
logger = getLogger(__name__)
handler = StreamHandler()
handler.setLevel(DEBUG)
logger.setLevel(DEBUG)
logger.addHandler(handler)


class IpmsgServer(threading.Thread):

    src_host = "0.0.0.0"
    # TODO
    sended_que_life_time = 30
    received_que_life_time = 100

    def __init__(self, user_name, group_name, use_port=2524):
        """
        IPMSGを管理するメインクラス。

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

        # パケット番号はユニークじゃないといけないので起動時にベースを決める
        rnd = random.Random()
        self.packet_no = rnd.randint(1, 100000)
        # UDPのソケットつくる
        # ブロードキャストも設定
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind((self.src_host, self.use_port))

        # send_que -> sended_que -> age out
        # 送信待ちのキュー
        self.send_que = deque()
        # recvmsgパケットが届くのをまっているメッセージを格納するキュー
        self.sended_que = deque()
        # sendmsgで受け取ったキュー
        # 受信箱
        self.received_que = deque()


        # メンバーリストはニックネームをキーとする
        # {
        #   denzow: HostInfo(osuser:B1308-66-01:0:192.168.24.97:41482:denzow:ymsft_group),
        #   :
        # }
        self.host_list_dict = {}

        # ネットワークにブロードキャストして参加を通知する
        self._entry()
        # ほかのメンバーにホストリストをリクエストする
        self._request_host_list()

    def run(self):
        """
        メインループ
        :return:
        """
        logger.debug("Start listen.")
        # main loop
        try:
            while not self.stop_event.is_set():
                r, w, e = select.select([self.sock], [self.sock], [], 0)
                time.sleep(0.1)
                # print((r, w, e))
                # メッセージがきていればここで処理する
                for sk in r:
                    data, (ip, port) = sk.recvfrom(0x80000)
                    # パケットをIPMSGのフォーマットとしてパース
                    ip_msg = IpmsgMessageParser(ip, port, com.to_unicode(data))
                    # commad属性に応じた処理を行う
                    self.dispatch_action(ip_msg)

                # 送信待ちキューがあれば処理する
                if w and self.send_que:
                    # キューを全部さばく
                    while self.send_que:
                        # FIFO
                        send_msg = self.send_que.popleft()
                        logger.debug("To[%s:%s]" % (send_msg.addr, send_msg.port))
                        [logger.debug("\t"+x) for x in send_msg.check_flag()]
                        logger.debug(send_msg.get_full_message())
                        # 指定アドレスにメッセージを投げる
                        self.sock.sendto(send_msg.get_full_message(), (send_msg.addr, send_msg.port))

                        if send_msg.is_sendmsg():
                            # sendmsgのメッセージだけがrecvmsgによる受信確認が必要なので
                            # 格納しておく
                            # ただ、recvmsgをいつまでも保持したくないのでエージアウト用に時間を記録する
                            send_msg.born_now()
                            self.sended_que.append(send_msg)
                # メッセージキューのメンテナンス
                self._cleanup_ques()
        except Exception as e:
            error_args = sys.exc_info()
            logger.debug(traceback.print_tb(error_args[2]))
            logger.debug(e)

        # 終了時にソケットを閉じる
        self.sock.close()
        # self.sock = None
        logger.debug("closed socket")

    #########################
    # PUBLIC METHOD
    #########################
    def is_valid(self):
        """
        サーバが起動しているかを確認する
        :return:
        """
        sock_name = None
        try:
            sock_name = self.sock.getsockname()
        except:
            pass

        return sock_name is not None


    def stop(self):
        """
        サーバを停止する。ただし、即座に停止はせずメインループの終了フラグを設定する
        :return:
        """
        self.stop_event.set()

    def send_message(self, to_addr, msg):
        """
        メッセージを送信する。実際は送信待ちキューへの追加
        :param to_addr:送信先アドレス
        :param msg:送るメッセージの文字列
        :return:送信完了追跡用のパケット番号
        """
        # Ver(1) : Packet No : MyUserName : MyHostName : Command : Extra

        packet_no = self._get_packet_no()
        # 送信に必要な情報を添えてIpmsgMessageインスタンスにする
        ip_msg = IpmsgMessage(to_addr, self.use_port, msg, packet_no, self.user_name)
        # IPMSG_SENDMSGフラグを
        ip_msg.set_sendmsg()
        self._send(ip_msg)

        return packet_no

    def check_sended_message(self, packet_no):
        """
        指定されたパケット番号のメッセージが送信済みかを確認する.
        ただし、AgeOutの場合でもTrueになるので注意
        :param packet_no: 確認するパケット番号
        :return: 送信済みかどうか
        """
        # 送信待ちか送信後キューの両方から消えていれば送信は完了
        return not ((packet_no in [x.packet_no for x in self.sended_que]) or (packet_no in [x.packet_no for x in self.send_que]))

    def send_message_by_nickname(self, nickname, msg):
        """
        ユーザリストのニックネーム指定でメッセージを送信する
        :param nickname:  送信対象のユーザ名
        :param msg: 送るメッセージの文字列
        :return: 送信完了追跡用のパケット番号
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
        ユーザリストのニックネーム指定でメッセージを送信する
        ただしユーザ名は空白違いなどをある程度無視できる
        :param nickname:  送信対象のユーザ名
        :param msg: 送るメッセージの文字列
        :return: 送信完了追跡用のパケット番号
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
            logger.debug(rule_func(*rule_arg))
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
        指定されたニックネームのホスト情報を戻す
        :param nickname:
        :return:
        """
        return self.host_list_dict.get(nickname, None)

    #########################
    # ACTION LIST
    #########################
    def dispatch_action(self, ip_msg):
        """
        メッセージのcommandに応じてアクションに割りあてる
        :param ip_msg:
        :return:
        """
        logger.debug("from[%s:%s]" % (ip_msg.addr, ip_msg.port))
        # TODO debug
        [logger.debug("\t"+x) for x in ip_msg.check_flag()]

        # TODO フラグが複数ある場合の処理をちゃんと考えないと・・・

        # IP_RECVMSG
        if ip_msg.is_recvmsg():
            self.recvmsg_action(ip_msg)

        # IP_ANSENTRY
        if ip_msg.is_ansentry():
            self.ansentry_action(ip_msg)

        # IP_GETLIST
        if ip_msg.is_getlist():
            self.getlist_action(ip_msg)

        # BR_ENTRYとANSENTRYが同時の場合はほかのユーザが
        # ネットワークに参加したときに発生する
        if ip_msg.is_br_entry() and not ip_msg.is_ansentry():
            self.br_entry_with_ansentry_action(ip_msg)

        # okgetlist message have getlist flag too.
        # OKGETLISTはホストリスト返答可能フラグ
        # 返答でくるOKGETLISTはGETLISTとセットでくるので
        # 両方セットを無視しないと、ループしてしまう
        if ip_msg.is_okgetlist() and not ip_msg.is_getlist():
            self.okgetlist_action(ip_msg)

        # ほかのホストからメッセージを受信時はSENDMSGが立つ
        # RECVMSGを戻す
        if ip_msg.is_sendmsg():
            self.sendmsg_action(ip_msg)

        # デバッグ用。受け取ったメッセージをとりあえず表示するだけ
        self.default_action(ip_msg)

        # TODO こっちで登録したホストはニックネーム化けてるときがある
        # とりあえず受信したメッセージの送信元はホストリストにいれとく
        self._add_host_list(IpmsgHostinfoParser(ip_msg))

    def default_action(self, msg):
        """
        デバッグ用です
        :param msg:
        :return:
        """
        logger.debug("default:" + msg.get_full_unicode_message().__repr__())

    def recvmsg_action(self, msg):
        """
        IPMSG_RECVMSGはIPMSG_SENDCHECKOPTに対する返信なので
        受け取ったら紐づくメッセージを送信済みにする(キューから消す)
        紐づくかは、RECVMSGのメッセージ部分とパケット番号の比較で可能
        """
        logger.debug("recvmsg:" + msg.get_full_unicode_message())
        for s_msg in self.sended_que:

            # packet_no is not endwith \00
            if s_msg.packet_no == msg.message.rstrip("\00"):
                # logger.debug("send success:" + s_msg.get_full_message())
                self.sended_que.remove(s_msg)
                break

    def ansentry_action(self, msg):
        """
        ANSENTRYはBR_ENTRYの返答。自分がネットワーク参加時に
        他ホストから送信されるもの。
        (たしか)なにもしなくてよかったはず・・・

        :param msg:
        :return:
        """
        pass
        #logger.debug("ansentry:" + msg.get_full_message().__repr__())

    def okgetlist_action(self, msg):
        """
        OKGETLISTを受け取ったら、相手にGETLISTを投げてホストリストを
        要求する
        :param msg:
        :return:
        """
        # add hostlist
        #logger.debug("okgetlist:" + msg.get_full_message())
        # "1:100:sender:sender-pc:18:0"

        ip_msg = IpmsgMessage(msg.addr, msg.port, "", self._get_packet_no(), self.user_name)
        ip_msg.set_flag(c.IPMSG_GETLIST)
        self._send(ip_msg)

    # TODO ホストリストが長い場合のプロトコルに対応できていない
    def getlist_action(self, msg):
        """
        GETLISTを受け取ったら、ホストリストを解釈し登録する

        :param msg:
        :return:
        """
        #logger.debug("getlist:" + msg.get_full_message().__repr__())
        logger.debug("getlist")
        begin_no, host_count, host_list = IpmsgHostinfoListParser(msg.get_full_unicode_message())
        for host in host_list:
            self._add_host_list(host)

    def br_entry_with_ansentry_action(self, msg):
        """
        BR_ENTRYを受け取ったらANSENTRYを戻して相手に自分を伝える。
        さらに送信元を自分のホストリストに追加する
        :param msg:
        :return:
        """
        logger.debug("br_entry:" + msg.get_full_message().__repr__())
        send_msg = "%s\00%s" % (self.user_name, self.group_name)
        ip_msg = IpmsgMessage(msg.addr, msg.port, send_msg, self._get_packet_no(), self.user_name)
        ip_msg.set_flag(c.IPMSG_ANSENTRY)
        logger.debug("br_entry_re:" + ip_msg.get_full_message().__repr__())
        self._send(ip_msg)

    def sendmsg_action(self, msg):
        """
        ほかのホストからメッセージを受け取ったときのアクション
        :param msg:
        :return:
        """
        logger.debug("sendmsg:" + msg.get_full_unicode_message())

        # SENDCHEKOPTならRECVMSGを戻さないと相手は受信したことがわからない
        if msg.is_sendcheckopt():
            ip_msg = IpmsgMessage(msg.addr, msg.port, msg.packet_no, self._get_packet_no(), self.user_name)
            ip_msg.set_flag(c.IPMSG_RECVMSG)
            self._send(ip_msg)

        msg.born_now()
        self.received_que.append(msg)

    ####################
    # INTERNAL METHOD
    #####################

    def _entry(self):
        """
        ネットワークに参加
        ブロードキャストで伝える
        """
        # Ver : PacketNo : User : Host : Command : Msg
        #send_msg = "1:%s:sayamada:B1308-66-01:%d:sayamada\00sayamada_group\00" % (self.get_packet_no(), command)
        send_msg = "%s\00%s" % (self.user_name, self.group_name)

        ip_msg = IpmsgMessage("255.255.255.255", self.use_port, send_msg, self._get_packet_no(), self.user_name)
        ip_msg.set_flag(c.IPMSG_BR_ENTRY)
        # todo 任意のアドレスにもブロードキャストできるべき
        self._send(ip_msg)

    def _request_host_list(self):
        """
        IPMSG_BR_ISGETLIST2を送信しホストリストを送ってくれるを探す
        :return:
        """
        #1:801798212:root:falcon:6291480:(\00)
        ip_msg = IpmsgMessage("255.255.255.255", self.use_port, "", self._get_packet_no(), self.user_name)
        ip_msg.set_flag(c.IPMSG_BR_ISGETLIST2)
        self._send(ip_msg)

    def _get_packet_no(self):
        """
        インクリメントしてパケット番号を戻す
        送信メッセージは文字列なので文字列で戻している
        """
        self.packet_no += 1
        # msg is not int. so packet_no must be str too.
        return unicode(self.packet_no)

    def _send(self, ip_msg):
        """
        送信キューに追加
        :param ip_msg:
        :return:
        """
        self.send_que.append(ip_msg)

    def _add_host_list(self, host_info):
        """
        IpmsgHostinfoインスタンスをうけとり
        nick_nameをキーに登録する
        :param host_info:
        :return:
        """
        self.host_list_dict[host_info.nick_name] = host_info

    def _cleanup_ques(self):
        """
        だいぶ古い送信完了確認キューを待機する
        :return:
        """

        now = datetime.datetime.now()
        aged_out_list = [msg for msg in self.sended_que if (now - msg.born_time) > datetime.timedelta(seconds=self.sended_que_life_time)]
        for msg in aged_out_list:
            logger.debug("Age out:[%s:%s]" % (msg.packet_no, msg.addr))
            self.sended_que.remove(msg)


class IpmsgException(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return repr(self.message)
