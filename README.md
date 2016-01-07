# ipymessenger

It's not completed.

## how to

check sample.py

```python
# username, group name, port(default 2524)
ip = IpmsgServer("denzow", "denzow_group", 2721)

# start (it's threading)
ip.start()

# send message
# パケットNOが戻ります。これはメッセージの送信成功のチェックに必要です
# ※送信先が存在しなくてもIPMSGプロトコルでは失敗しません。
packet_no = ip.send_message("192.168.1.xx", "hello")

# check succeed?
# 相手からIPMSG_RECVMSGを受信するまでは送信済キューにメッセージを保存します。
# 受信した時点でキューから取り出す実装です。キューにメッセージがあるかをチェックすることで
# 送信状況が識別できます
ip.check_sended_message(packet_no)

# get host info
# 同一N/Wの他ホストの情報を取得します
# これにより、ニックネームから送信先のアドレスを割り出すことができます
testusers_info = ip.get_hostinfo_by_nickname("testuser")
packet_no = ip.send_message(testusers_info.addr, "hello")

# stop server
# wait stop thread and close socket.
ip.stop()

```


## TODO

* send SECRET message
* recv SECRET message
* register hostinfo correctry other than via getlist
* remove hostlist when rcv br_exit.