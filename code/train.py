# -*- coding: utf-8 -*-
from __future__ import print_function
import os
import argparse
import sys
from utils import merge, train
import pickle

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', action='store', dest='dir', help='malware traffic log folder')
    parser.add_argument('--output', action='store', dest='output', help='storage path of malware fingerprints')
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

    fp = train(list(sequences.values()))
    print(fp)
    pickle.dump(fp, open(args.output, 'wb'))
