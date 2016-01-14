# ipymessenger

Pythonで[IP messenger](http://ipmsg.org/) を使うためのライブラリです。
そのうちPyPIにも登録したいですがまだです。

ライブりとして組み込んで使用することを想定しています。


## 関数の説明

メインのIpmsgServerの各関数は以下のDocをごらんください
[pydoc]("./IpmsgServer.html")



## サンプル

### 簡単な使い方

```python
import time
from ipymessenger.IpmsgServer import IpmsgServer

# 送信先
dest_host = "192.168.1.xx"
ip = IpmsgServer("denzow", "ymsft_group")

# サーバスタート
ip.start()

# send message
# パケットNOが戻ります。これはメッセージの送信成功のチェックに必要です
# ※送信先が存在しなくてもIPMSGプロトコルでは失敗しません。
packet_no = ip.send_message(dest_host, "hello")

# 送信済みになるには少し待つ必要があります
time.sleep(5)

# 相手からIPMSG_RECVMSGを受信するまでは送信済キューにメッセージを保存します。
# 受信した時点でキューから取り出す実装です。キューにメッセージがあるかをチェックすることで
# 送信状況が識別できます
ip.check_sended_message(packet_no)


# 同一N/Wの他ホストの情報を取得します
# これにより、ニックネームから送信先のアドレスを割り出すことができます
testusers_info = ip.get_hostinfo_by_nickname("testuser")
packet_no = ip.send_message(testusers_info.addr, "hello")

# IPアドレスがわからなくても、ニックネーム経由でメッセージを送信します
packet_no = ip.send_message_by_nickname("", "hello")

# IPアドレスがわからなくても、ニックネーム経由でメッセージを送信します
# ニックネームの空白とかが曖昧でも可能な限り頑張って探します。
# この例では以下を試します
# hogefoo/hoge foo/hoge  foo/hoge　foo
packet_no = ip.send_message_by_fuzzy_nickname("hoge foo", "hello")

# 届いているメッセージを読みます
# 指定したIPから届いているメッセージについてリストで戻します。
# numで何通取り出すか指定します
message_list = ip.get_message(dest_host, num=10)


# stop server
# これをコールせずにメインスレッドを終えるとIpmsgServerスレッドの終了まちになります
ip.stop()
```

## 注意事項

### check_sended_message

パケット番号を引数にとり、送信完了しているかを確認しますがsend_message系の処理は非同期で
処理されている点や、送信後に相手から返答パケットを受け取って初めて送信完了になるため
以下のようなコードはかならずFalseを戻します。

```python
packet_no = ip.send_message("192.168.1.xx", "hello")
ip.check_sended_message(packet_no) # -> 99% Falseになります
```

そのため以下のように少しsleepをいれるか、Trueになるまで待機させる様に使ってください。

```python
packet_no = ip.send_message("192.168.1.xx", "hello")
time.sleep(5) # 5秒は経験則です。N/W次第かと
ip.check_sended_message(packet_no) # 95% True
```

```python
packet_no = ip.send_message("192.168.1.xx", "hello")
sended = False
timeout_limit = 100
try_count = 0
while try_count < timeout_limit:

    time.sleep(0.1) # ループごとの待機時間はCPUと相談してください。
    try_count += 1
    if(ip.check_sended_message(packet_no)):
        break
else:
    raise Exception("Time out")
```



## 制限事項

* 添付ファイルつかえません
* 暗号化はできません

## TODO

* send SECRET message
* register hostinfo correctry other than via getlist
* remove hostlist when rcv br_exit.