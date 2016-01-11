# ipymessenger

Library for [IP messenger](http://ipmsg.org/) .

## how to use

```
# username, group name, port(default 2524)
ip = IpmsgServer("denzow", "denzow_group", 2721)

# start server
ip.start()


# send message
packet_no = ip.send_message("192.168.1.xx", "hello")

# check succeed?( should wait some seconds.)
ip.check_sended_message(packet_no)

# get host info
testusers_info = ip.get_hostinfo_by_nickname("testuser")
packet_no = ip.send_message(testusers_info.addr, "hello")

# send message use nickname without ip addr
packet_no = ip.send_message_by_nickname("", "hello")

# send message use fuzzy nickname without ip addr
packet_no = ip.send_message_by_fuzzy_nickname("", "hello")


# stop server
# wait stop thread and close socket.
ip.stop()

```

## restrict

* never use attach file.
* nerver encrypt

## TODO

* send SECRET message
* recv SECRET message
* register hostinfo correctry other than via getlist
* remove hostlist when rcv br_exit.