#!/usr/bin/env python
# coding:utf-8

import re

"""
util functions
"""

def to_unicode(string):
    """
    avoid decode error.
    :param string:
    :return:
    """
    encode = guess_charset(string)
    # print encode, string
    try:
        return string.decode(encode)
    except UnicodeDecodeError:
        return string.decode(encode, "ignore")


def guess_charset(data):
    try:
        data.decode("shift-jis")
        return "shift-jis"
    except:
        pass
    try:
        data.decode("utf-8")
        return "utf-8"
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
        return "shift-jis"


def adjust_name(base_name_str, join_str):
    return join_str.join(re.split("\s+", base_name_str))
