# -*- coding: utf-8 -*-
from __future__ import print_function
import sys
import time
from zat import zeek_log_reader
from zat.utils import dir_watcher, signal_utils


def fun(file_path):
    print(file_path)


def my_exit():
    """Exit on Signal"""
    print('Goodbye...')
    sys.exit()


dir_watcher.DirWatcher('', callback=fun)
with signal_utils.signal_catcher(my_exit):
    while True:
        time.sleep(.5)
