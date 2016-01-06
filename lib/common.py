#!/usr/bin/env python
# coding:utf-8

"""
util functions
"""

def to_unicode(string):
    encode = guess_charset(string)
    try:
        return string.decode(encode)
    except UnicodeDecodeError:
        return string.decode(encode, "ignore")


def guess_charset(data):
    # 日本語の主要コーディングで試す
    # 渡された文字列について、decodeし
    # 成功したコードを戻す
    try:
        data.decode("utf-8")
        return "utf-8"
    except:
        pass
    try:
        data.decode("shift-jis")
        return "shift-jis"
    except:
        pass
    try:
        data.decode("euc-jp")
        return "euc-jp"
    except:
        pass
    try:
        data.decode("iso2022-jp")
        return "iso2022-jp"
    except:
        pass
    try:
        data.decode("CP932")
        return "CP932"
    except:
        return "utf-8"
