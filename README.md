# ipymessenger

Pythonで[IP messenger](http://ipmsg.org/) を使うためのライブラリです。
そのうちPyPIにも登録したいですがまだです。

ライブりとして組み込んで使用することを想定しています。

## how to use

 sample.py からお察しください。

```python
from IpmsgServer import IpmsgServer

# username, group name, port(default 2524)
ip = IpmsgServer("denzow", "denzow_group", 2721)

# サーバスタート
ip.start()

# send message
# パケットNOが戻ります。これはメッセージの送信成功のチェックに必要です
# ※送信先が存在しなくてもIPMSGプロトコルでは失敗しません。
packet_no = ip.send_message("192.168.1.xx", "hello")

# check succeed?( should wait some seconds.)
# 相手からIPMSG_RECVMSGを受信するまでは送信済キューにメッセージを保存します。
# 受信した時点でキューから取り出す実装です。キューにメッセージがあるかをチェックすることで
# 送信状況が識別できます
ip.check_sended_message(packet_no)

# get host info
# 同一N/Wの他ホストの情報を取得します
# これにより、ニックネームから送信先のアドレスを割り出すことができます
testusers_info = ip.get_hostinfo_by_nickname("testuser")
packet_no = ip.send_message(testusers_info.addr, "hello")

# send message use nickname without ip addr
# IPアドレスがわからなくても、ニックネーム経由でメッセージを送信します
packet_no = ip.send_message_by_nickname("", "hello")

# send message use fuzzy nickname without ip addr
# IPアドレスがわからなくても、ニックネーム経由でメッセージを送信します
# ニックネームの空白とかが曖昧でも可能な限り頑張って探します。
packet_no = ip.send_message_by_fuzzy_nickname("", "hello")


# stop server
# wait stop thread and close socket.
ip.stop()

#
```

## 制限事項

* 添付ファイルつかえません
* 暗号化はできません
* (まだ)受け取ったメッセージは標準出力に書き出すだけです

## TODO

* send SECRET message
* recv SECRET message
* register hostinfo correctry other than via getlist
* remove hostlist when rcv br_exit.