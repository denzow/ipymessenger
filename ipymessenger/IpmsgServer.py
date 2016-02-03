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
from ipymessenger.common import to_unicode, adjust_name
from logging import getLogger, StreamHandler, DEBUG
logger = getLogger(__name__)
handler = StreamHandler()
handler.setLevel(DEBUG)


class IpmsgServer(threading.Thread):

    src_host = "0.0.0.0"

    def __init__(self, user_name, group_name="", use_port=2524, opt_debug_handler=None,
                 sended_que_life_time=6000, received_que_life_time=6000, wait_read_que_life_time=6000, broad_cast_addrs=None):
        """
        IPメッセンジャーを送受信するメインクラス
        スレッドで動作する


        :param user_name: 他のユーザに表示されるユーザ名
        :param group_name: 他のユーザに表示されるグループ名
        :param use_port: リスニングポート、送信時にも使用される
        :param opt_debug_handler: デバッグメッセージを書き出す場合にはlogging.StreamHandler等を渡す
        :param sended_que_life_time: 送信済メッセージがいつまでキューに保持されるか(秒)
        :param received_que_life_time: 受信メッセージがいつまでキューに保持されるか(秒)
        :param broad_cast_addrs: 255.255.255.255以外でブロードキャストパケットを送信するアドレス
                                 別セグメント等がいる場合は指定する
        :return: なし
        """

        super(IpmsgServer, self).__init__()
        self.daemon = True

        self.use_port = use_port
        self.user_name = user_name
        self.group_name = group_name

        if opt_debug_handler:
            logger.addHandler(opt_debug_handler)
            logger.setLevel(DEBUG)

        self.sended_que_life_time = sended_que_life_time
        self.received_que_life_time = received_que_life_time
        self.wait_read_que_life_time = wait_read_que_life_time
        # broadcast
        self.broad_cast_addrs = [
            "255.255.255.255"
        ]
        # 任意のブロードキャスト先を追加
        if broad_cast_addrs:
            if isinstance(broad_cast_addrs, list):
                self.broad_cast_addrs = self.broad_cast_addrs + broad_cast_addrs
            else:
                self.broad_cast_addrs.append(broad_cast_addrs)

        self.stop_event = threading.Event()
        # デフォルトのSENDMSGに対するハンドラはなにもしない
        self._sendmsg_handler = lambda x: None

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
        # 未開封キュー
        self.wait_read_que = deque()

        # メンバーリストはニックネームをキーとする
        # {
        #   denzow: HostInfo(osuser:B1308-66-01:0:192.168.24.97:41482:denzow:ymsft_group),
        #   :
        # }
        self.host_list_dict = {}

        # ネットワークにブロードキャストして参加を通知する
        self._entry()
        # ほかのメンバーにホストリストをリクエストする
        self._last_get_listed_time = None
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
                    logger.debug("raw message:")
                    logger.debug(data)
                    # パケットをIPMSGのフォーマットとしてパース
                    ip_msg = IpmsgMessageParser(ip, port, to_unicode(data))
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
                        logger.debug(send_msg.get_full_unicode_message())
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

                # ホストリストの更新が60秒前なら再度行う
                if (datetime.datetime.now() - self._last_get_listed_time) > datetime.timedelta(seconds=60):
                    self._request_host_list()

        except IndentationError as e:
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
        ソケットが有効かどうかで判断
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

    def send_message(self, to_addr, msg, is_secret=False):
        """
        メッセージを送信する。実際は送信待ちキューへの追加
        :param to_addr:送信先アドレス
        :param msg:送るメッセージの文字列
        :param is_secret: 封書として送るか
        :return:送信完了追跡用のパケット番号
        """
        # Ver(1) : Packet No : MyUserName : MyHostName : Command : Extra
        packet_no = self._get_packet_no()
        # 送信に必要な情報を添えてIpmsgMessageインスタンスにする
        ip_msg = IpmsgMessage(to_addr, self.use_port, msg, packet_no, self.user_name)
        # IPMSG_SENDMSGフラグを立てる
        ip_msg.set_sendmsg()

        if is_secret:
            ip_msg.set_secretopt()

        self._send(ip_msg)

        return packet_no

    def send_message_by_nickname(self, nickname, msg, is_secret=False):
        """
        ユーザリストのニックネーム指定でメッセージを送信する
        :param nickname:  送信対象のユーザ名
        :param msg: 送るメッセージの文字列
        :param is_secret: 封書として送るか
        :return: 送信完了追跡用のパケット番号
        """
        # Ver(1) : Packet No : MyUserName : MyHostName : Command : Extra

        host_info = self.get_hostinfo_by_nickname(nickname)

        if host_info:
            return self.send_message(host_info.addr, msg, is_secret=is_secret)
        else:
            raise IpmsgException("nickname matched host is not found.")

    def send_message_by_fuzzy_nickname(self, nickname, msg, is_secret=False):
        """
        ユーザリストのニックネーム指定でメッセージを送信する
        ただしユーザ名は空白違いなどをある程度無視できる
        :param nickname:  送信対象のユーザ名
        :param msg: 送るメッセージの文字列
        :param is_secret: 封書として送るか
        :return: 送信完了追跡用のパケット番号
        """
        # Ver(1) : Packet No : MyUserName : MyHostName : Command : Extra
        # rule list
        # (func, name + args)
        try_rule_list = [
            (lambda x: x, [nickname]),  # 1st do nothing
            (adjust_name, [nickname, ""]),
            (adjust_name, [nickname, " "]),  # single space
            (adjust_name, [nickname, "  "]),  # double single space
            (adjust_name, [nickname, "　"]),  # multi byte space
        ]
        host_info = None
        for rule_func, rule_arg in try_rule_list:
            logger.debug(rule_func(*rule_arg))
            host_info = self.get_hostinfo_by_nickname(rule_func(*rule_arg))
            if host_info:
                break

        if host_info:
            return self.send_message(host_info.addr, msg, is_secret=is_secret)
        else:
            raise IpmsgException("nickname fuzzy matched host is not found.")

    def send_message_by_osusername(self, username, msg, is_secret=False):
        """
        ユーザリストのニックネーム指定でメッセージを送信する
        :param username:  送信対象のユーザ名
        :param msg: 送るメッセージの文字列
        :param is_secret: 封書として送るか
        :return: 送信完了追跡用のパケット番号
        """
        # Ver(1) : Packet No : MyUserName : MyHostName : Command : Extra

        host_info = self.get_hostinfo_by_osusername(username)

        if host_info:
            return self.send_message(host_info.addr, msg, is_secret=is_secret)
        else:
            raise IpmsgException("username matched host is not found.")

    def check_sended_message(self, packet_no):
        """
        指定されたパケット番号のメッセージが送信済みかを確認する.
        ただし、AgeOutの場合でもTrueになるので注意
        :param packet_no: 確認するパケット番号
        :return: 送信済みかどうか
        """
        # 送信待ちか送信後キューの両方から消えていれば送信は完了
        return not ((packet_no in [x.packet_no for x in self.sended_que]) or (packet_no in [x.packet_no for x in self.send_que]))

    def check_readed_message(self, packet_no):
        """
        指定されたパケット番号のメッセージが送信済みかを確認する.
        ただし、AgeOutの場合でもTrueになるので注意
        :param packet_no: 確認するパケット番号
        :return: 送信済みかどうか
        """
        # 送信後キューと開封まちキューの両方から消えていれば送信は完了
        return not ((packet_no in [x.packet_no for x in self.wait_read_que]) or (packet_no in [x.packet_no for x in self.sended_que]))

    def get_hostinfo_by_nickname(self, nickname):
        """
        指定されたニックネームのホスト情報を戻す
        :param nickname: 情報を取得したいニックネーム
        :return: IpmsgHostinfoインスタンス or None
        """
        ret = None
        for nick in self.host_list_dict:
            if nickname in nick:
                ret = self.host_list_dict[nick]

        return ret

    def get_hostinfo_by_osusername(self, username):
        """
        指定されたユーザー名のホスト情報を戻す
        :param username: 情報を取得したいユーザ名
        :return: IpmsgHostinfoインスタンス or None
        """
        ret = None
        for host_info in self.host_list_dict.values():
            if username in host_info.user_name:
                ret = host_info

        return ret

    def get_hostinfo_by_addr(self, addr, port):
        """
        指定されたアドレスのホスト情報を戻す
        :param addr: 対象IPアドレス
        :param port: 対象ポート
        :return: IpmsgHostinfoインスタンス or None
        """
        ret = None
        for host_info in self.host_list_dict.values():
            if addr == host_info.addr and port == host_info.port:
                ret = host_info
        return ret

    def set_sendmsg_handler(self, function):
        """
        IPMSG_SENDMSG(他のホストからのメッセージ受信)のメッセージが届いた時の
        処理関数を登録する
        :param function: IpmsgMessageを取る関数
        :return: 無し
        """
        self._sendmsg_handler = function

    def get_message(self, from_addr, num=1, remove=False):
        """
        送信元アドレス指定で受信メッセージを取り出す。デフォルトでは1通のみ
        取り出す。またデフォルトでは取り出してもメッセージはキューに残る

        封書の場合は取り出した時点で開封通知が相手に届く

        :param from_addr: 取得したいメッセージの送信元アドレス
        :param num: 何通取り出すか。指定数未満のメッセージしない場合でもある限り取得する
        :param remove: 取得したメッセージをキューから削除するか(default=false)
        :return: IpmsgMessageインスタンスのリスト
        """
        matched_received_list = [msg for msg in self.received_que if msg.addr == from_addr][0:num]

        for msg in matched_received_list:
            # 削除処理
            if remove:
                logger.debug("Remove rcv:[%s:%s]" % (msg.packet_no, msg.addr))
                self.received_que.remove(msg)

            # 封書の場合は開封パケットを送る
            # remove=Falseだと何回か開封パケットが飛ぶがエラーにはならないようなのでよしとする
            if msg.is_secretopt():
                ip_msg = IpmsgMessage(msg.addr, msg.port, msg.packet_no, self._get_packet_no(), self.user_name)
                ip_msg.set_flag(c.IPMSG_READMSG)
                self._send(ip_msg)

        return matched_received_list


    #########################
    # ACTION LIST
    #########################
    def dispatch_action(self, ip_msg):
        """
        メッセージのcommandに応じてアクションに割りあてる
        :param ip_msg: 受信メッセージ
        :return:
        """
        logger.debug("from[%s:%s]" % (ip_msg.addr, ip_msg.port))
        # TODO debug
        [logger.debug("\t"+x) for x in ip_msg.check_flag()]

        # TODO フラグが複数ある場合の処理をちゃんと考えないと・・・

        # メッセージが無事に届いた
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
        if ip_msg.is_br_entry():
            if not ip_msg.is_ansentry():
                self.br_entry_action(ip_msg)
            if ip_msg.is_ansentry() and not ip_msg.is_okgetlist():
                self.br_entry_with_ansentry_action(ip_msg)

        # okgetlist message have getlist flag too.
        # OKGETLISTはホストリスト返答可能フラグ
        # 返答でくるOKGETLISTはGETLISTとセットでくるので
        # 両方セットを無視しないと、ループしてしまう
        if ip_msg.is_okgetlist() and not ip_msg.is_getlist():
            self.okgetlist_action(ip_msg)

        # ほかのホストからメッセージを受信時はSENDMSGが立つ
        # RECVMSGを戻す
        # recvmsgが立っている場合は、sendchkoptの返送なので無視
        if ip_msg.is_sendmsg():
            if ip_msg.is_recvmsg():
                pass
            elif ip_msg.is_readmsg():
                # 封書開封
                self.readmsg_action(ip_msg)

            else:
                self.sendmsg_action(ip_msg)

        if ip_msg.is_br_exit() and not ip_msg.is_br_entry():
            self.br_exit_action(ip_msg)

        # デバッグ用。受け取ったメッセージをとりあえず表示するだけ
        self.default_action(ip_msg)

        # TODO こっちで登録したホストはニックネーム化けてるときがある
        # とりあえず受信したメッセージの送信元はホストリストにいれとく
        #self._add_host_list(IpmsgHostinfoParser(ip_msg))

    def default_action(self, msg):
        """
        デバッグ用です
        :param msg: 受信メッセージ
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
                # 封書なら開封まちキューに移動
                if s_msg.is_secretopt():
                    self.wait_read_que.append(s_msg)

                break

    def ansentry_action(self, msg):
        """
        ANSENTRYはBR_ENTRYの返答。自分がネットワーク参加時に
        他ホストから送信されるもの。
        (たしか)なにもしなくてよかったはず・・・

        :param msg: 受信メッセージ
        :return:
        """
        pass
        #logger.debug("ansentry:" + msg.get_full_message().__repr__())

    def okgetlist_action(self, msg):
        """
        OKGETLISTを受け取ったら、相手にGETLISTを投げてホストリストを
        要求する
        :param msg: 受信メッセージ
        :return:
        """
        # add hostlist
        #logger.debug("okgetlist:" + msg.get_full_message())
        # "1:100:sender:sender-pc:18:0"
        ip_msg = IpmsgMessage(msg.addr, msg.port, str(0), self._get_packet_no(), self.user_name)
        ip_msg.set_flag(c.IPMSG_GETLIST)
        self._send(ip_msg)

    # TODO ホストリストが長い場合のプロトコルに対応できていない
    def getlist_action(self, msg):
        """
        GETLISTを受け取ったら、ホストリストを解釈し登録する

        :param msg: 受信メッセージ
        :return:
        """
        #logger.debug("getlist:" + msg.get_full_message().__repr__())
        logger.debug("getlist")
        try:
            begin_no, host_count, host_list = IpmsgHostinfoListParser(msg.message)
            for host in host_list:
                self._add_host_list(host)

            # TODO wip
            # 残りのホスト要求
            # host_countが0でなければ続きを依頼し、0になるまで依頼する
            # continus flagがよくわからない・・・
            #if host_count != 0:
            #    # begin_no + host_count
            #    ip_msg = IpmsgMessage(msg.addr, msg.port, str(1), self._get_packet_no(), self.user_name)
            #    ip_msg.set_flag(c.IPMSG_GETLIST)
            #    logger.debug("getlist_more:" + ip_msg.get_full_message().__repr__())
            #    self._send(ip_msg)

        except ValueError as e:
            logger.debug("parse hostlist error")
            logger.debug(e.message)

    def br_entry_action(self, msg):
        """
        BR_ENTRYを受け取ったらANSENTRYを戻して相手に自分を伝える。
        さらに送信元を自分のホストリストに追加する
        :param msg: 受信メッセージ
        :return:
        """
        logger.debug("br_entry:" + msg.get_full_message().__repr__())
        send_msg = "%s\00%s" % (self.user_name, self.group_name)
        ip_msg = IpmsgMessage(msg.addr, msg.port, send_msg, self._get_packet_no(), self.user_name)
        ip_msg.set_flag(c.IPMSG_ANSENTRY)
        logger.debug("br_entry_re:" + ip_msg.get_full_message().__repr__())
        self._send(ip_msg)
        # ホストリストへ追加
        self._add_host_list(IpmsgHostinfoParser(msg))

    def br_entry_with_ansentry_action(self, msg):
        """
        BR_ENTRYとANSENTRYがあるなら、それはこちらのBR_ENTRYへの
        返答。送信元をを自分のホストリストに追加する
        :param msg: 受信メッセージ
        :return:
        """
        logger.debug("br_entry_with_ans:" + msg.get_full_message().__repr__())
        # ホストリストへ追加
        self._add_host_list(IpmsgHostinfoParser(msg))

    def sendmsg_action(self, msg):
        """
        ほかのホストからメッセージを受け取ったときのアクション
        RECVMSGは無視
        :param msg: 受信メッセージ
        :return:
        """
        logger.debug("sendmsg:" + msg.get_full_unicode_message())
        # SENDCHEKOPTならRECVMSGを戻さないと相手は受信したことがわからない
        if msg.is_sendcheckopt():
            ip_msg = IpmsgMessage(msg.addr, msg.port, msg.packet_no, self._get_packet_no(), self.user_name)
            ip_msg.set_flag(c.IPMSG_RECVMSG)
            self._send(ip_msg)

        # RCVの場合はただの返答パケットなので無視しないといけない
        if not msg.is_recvmsg():
            self._sendmsg_handler(msg)
            msg.born_now()
            self.received_que.append(msg)

    def readmsg_action(self, msg):
        """
        封書の開封通知を受け取った時のアクション
        :param msg: 受信メッセージ(メッセージ部が封書だったメッセージのパケット番号)
        :return:
        """
        logger.debug("readmsg:" + msg.get_full_unicode_message())
        # SENDCHEKOPTならRECVMSGを戻さないと相手は受信したことがわからない
        for s_msg in self.wait_read_que:
            # packet_no is not endwith \00
            if s_msg.packet_no == msg.message.rstrip("\00"):
                # logger.debug("send success:" + s_msg.get_full_message())
                self.wait_read_que.remove(s_msg)
                break


    def br_exit_action(self, msg):
        """
        BR_EXITを受け取ったら送信ホストをホストリストから削除する
        :param msg: 受信メッセージ
        :return:
        """
        logger.debug("br_exit:" + msg.get_full_message().__repr__())
        logger.debug("br_exit:" + msg.message.__repr__())
        # TODO
        # メッセージ部分をつかわないといけない
        try:
            self.host_list_dict.pop(msg.username)
        except KeyError:
            pass


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

        for broad_addr in self.broad_cast_addrs:
            ip_msg = IpmsgMessage(broad_addr, self.use_port, send_msg, self._get_packet_no(), self.user_name)
            ip_msg.set_flag(c.IPMSG_BR_ENTRY)
            self._send(ip_msg)

    def _request_host_list(self):
        """
        IPMSG_BR_ISGETLIST2を送信しホストリストを送ってくれる相手を探す
        :return:
        """
        # 実行日を保持
        self._last_get_listed_time = datetime.datetime.now()
        #1:801798212:root:falcon:6291480:(\00)
        for broad_addr in self.broad_cast_addrs:
            ip_msg = IpmsgMessage(broad_addr, self.use_port, "", self._get_packet_no(), self.user_name)
            ip_msg.set_flag(c.IPMSG_BR_ISGETLIST2)
            self._send(ip_msg)

    def _get_packet_no(self):
        """
        インクリメントしてパケット番号を戻す
        送信メッセージは文字列なので文字列で戻している
        """
        self.packet_no += 1
        # msg is not int. so packet_no must be str too.
        return str(self.packet_no)

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
        life_timeに基づき以下のキューから削除を行う

        * 送信済キュー
        * 受信キュー
        * 開封待ちキュー

        :return:
        """

        now = datetime.datetime.now()
        # 送信済みメッセージのクリーンアップ
        aged_out_sended_list = [msg for msg in self.sended_que if (now - msg.born_time) > datetime.timedelta(seconds=self.sended_que_life_time)]
        for msg in aged_out_sended_list:
            logger.debug("Age out sended:[%s:%s]" % (msg.packet_no, msg.addr))
            self.sended_que.remove(msg)

        # 受信メッセージのクリーンアップ
        aged_out_received_list = [msg for msg in self.received_que if (now - msg.born_time) > datetime.timedelta(seconds=self.received_que_life_time)]
        for msg in aged_out_received_list:
            logger.debug("Age out rcv:[%s:%s]" % (msg.packet_no, msg.addr))
            self.received_que.remove(msg)

        # 開封待ちキューのクリーンアップ
        aged_out_read_wait_list = [msg for msg in self.wait_read_que if (now - msg.born_time) > datetime.timedelta(seconds=self.wait_read_que_life_time)]
        for msg in aged_out_read_wait_list:
            logger.debug("Age out readwait:[%s:%s]" % (msg.packet_no, msg.addr))
            self.wait_read_que.remove(msg)


class IpmsgException(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return repr(self.message)
