# -*- coding: utf-8 -*-
from __future__ import print_function
import os
import argparse
import sys
from utils import merge, get_prob
import pickle

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', action='store', dest='dir', help='malware traffic log folder')
    parser.add_argument('--fp', action='store', dest='fp', help='storage path of malware fingerprints')
    args = parser.parse_args()

    if not os.path.exists(args.dir):
        print('folder({}) is not exists.'.format(args.dir))
        sys.exit(1)
    files = os.listdir(args.dir)
    required_files = ['conn.log']
    for filename in required_files:
        if filename not in files:
            print('{} is not exists.'.format(filename))
            sys.exit(1)

    optional_files = ['dns.log', 'http.log', 'ssl.log']
    for filename in required_files:
        if filename not in files:
            print('Warning: {} is not exists.'.format(filename))

    sequences = merge(args.dir)

    fp = pickle.load(open(args.fp, 'rb'))
    tp = 0
    for key in sequences:
        prob = get_prob(sequences[key], fp)
        if prob > 1e-50:
            tp += 1
    print(tp, len(sequences))
