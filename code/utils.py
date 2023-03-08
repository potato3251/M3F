# -*- coding: utf-8 -*-
from __future__ import print_function
import os
import argparse
import sys
import json
import re
import math
import numpy as np
from collections import defaultdict
from tqdm import tqdm


def norm(num):
    zero = 1
    while num > 10:
        num /= 10
        zero *= 10
    return int(num) * zero


def flow2status(flow):
    if flow['service'] == 'dns':
        if 'qtype' not in flow:
            flow['qtype'] = 1
        return '{}-{}-{}'.format(flow['service'], flow['qtype'], len(flow['answers']))
    return flow['service'], norm(flow['orig_bytes']), norm(flow['resp_bytes'])


def train(train_data):
    trans_matrix = {}
    for seq in train_data:
        for idx in range(1, len(seq) - 1):
            current_status = seq[idx]
            next_status = seq[idx + 1]
            if current_status not in trans_matrix:
                trans_matrix[current_status] = {}
            if next_status not in trans_matrix[current_status]:
                trans_matrix[current_status][next_status] = 0
            trans_matrix[current_status][next_status] += 1
    for current_status in trans_matrix:
        total = 0
        for next_status in trans_matrix[current_status]:
            total += trans_matrix[current_status][next_status]
        for next_status in trans_matrix[current_status]:
            trans_matrix[current_status][next_status] /= total
    return trans_matrix


def sim(status, status_):
    if type(status) == tuple and type(status_) == tuple:
        if status_[0] != status[0]:
            return 0
        sim_prob = ((status[2] - status_[2]) ** 2 + (status[1] - status_[1]) ** 2) / (status[2] ** 2 + status[1] ** 2)
        sim_prob = np.clip(1 - math.sqrt(sim_prob), 0, 1)
        return sim_prob
    else:
        return 1 if status_ == status else 0


def get_prob(seq, trans_matrix):
    prob = 1
    for idx in range(1, len(seq) - 1):
        current_status = seq[idx]
        next_status = seq[idx + 1]
        if current_status in trans_matrix:
            max_prob = 0
            for status in trans_matrix[current_status]:
                trans_prob = sim(status, next_status) * trans_matrix[current_status][status]
                if max_prob < trans_prob:
                    max_prob = trans_prob
            prob *= max_prob
        else:
            prob *= 0
    return prob


def merge(dir_path):
    services = {'http', 'dns', 'ssl', 'tcp'}
    ignore_domain = {'time.windows.com', 'www.download.windowsupdate.com',
                     'windowsupdate.microsoft.com', }
    sequences = defaultdict(list)
    time_delta = 120
    full_path = os.path.join(dir_path, 'conn.log')
    dns_full_path = os.path.join(dir_path, 'dns.log')
    fr = open(dns_full_path)
    dns_lines = fr.readlines()
    fr.close()

    dns_flows = {}
    ip2id = {}
    ignore_ip = set()
    domain2id = {}
    for line in tqdm(dns_lines, desc='dns'):
        item = json.loads(line)
        if 'qtype' not in item or item['qtype'] != 1:
            continue
        if 'rcode' not in item or item['rcode'] != 0:
            continue
        if 'answers' not in item or len(item['answers']) == 0:
            continue
        if item['id.resp_h'].startswith('10.') or \
                item['id.resp_h'].startswith('127.0.0') or \
                item['id.resp_h'].startswith('192.168.'):
            ignore_ip.add(item['id.resp_h'])
        if item['query'] in ignore_domain:
            if 'answers' in item:
                for a in item['answers']:
                    if re.match('^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$', a) is None:
                        continue
                    ignore_ip.add(a)
            continue
        sub = item['query'].split('.')
        tld = '.'.join(sub[-3:])
        if tld not in domain2id:
            domain2id[tld] = len(domain2id)
        dns_flows[item['uid']] = set()
        idx = domain2id[tld]
        for a in item['answers']:
            if re.match('^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$', a) is None:
                continue
            dns_flows[item['uid']].add(a)
            if a in ip2id:
                idx = ip2id[a]
        for a in item['answers']:
            if re.match('^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$', a) is None:
                continue
            ip2id[a] = idx

    http_full_path = os.path.join(dir_path, 'http.log')
    if os.path.exists(http_full_path):
        fr = open(http_full_path)
        http_lines = fr.readlines()
        fr.close()
    else:
        http_lines = []

    fr = open(full_path)
    conn_lines = fr.readlines()
    conn_lines = conn_lines + dns_lines + http_lines
    fr.close()
    flows = {}
    for line in tqdm(conn_lines, desc='logs'):
        item = json.loads(line)
        if 'service' in item and item['service'] == 'http':
            continue
        if 'request_body_len' in item and 'response_body_len' in item:
            if 'method' not in item:
                continue
            if 'host' in item and item['host'].endswith('windowsupdate.com'):
                continue
            item['service'] = 'http'
            item['orig_bytes'] = item['request_body_len'] + 1
            item['resp_bytes'] = item['response_body_len'] + 1
        if item['id.resp_p'] == 53 and 'trans_id' in item:
            if 'query' not in item:
                continue
            if item['query'] in ignore_domain:
                continue
            if 'answers' in item:
                for a in item['answers']:
                    if re.match('^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$', a) is None:
                        continue
                    if a not in ip2id:
                        ip2id[a] = len(ip2id)
                    if ip2id[a] not in flows:
                        flows[ip2id[a]] = {}
                    item['service'] = 'dns'
                    flows[ip2id[a]][item['uid'] + str(item['ts'])] = item
            continue
        if 'service' in item:
            service = item['service']
        else:
            service = item['proto']
        if service not in services:
            continue
        if 'orig_bytes' not in item or 'resp_bytes' not in item:
            continue
        if item['orig_bytes'] == 0 and item['resp_bytes'] == 0:
            continue
        if service == 'dns':
            continue
        if item['id.resp_h'].startswith('10.') or \
                item['id.resp_h'].startswith('127.0.0') or \
                item['id.resp_h'].startswith('192.168.'):
            continue
        item['service'] = service
        dip = item['id.resp_h']
        if dip not in ignore_ip:
            if dip not in ip2id:
                ip2id[dip] = len(ip2id)
            if ip2id[dip] not in flows:
                flows[ip2id[dip]] = {}
            if item['service'] == 'http' and item['uid'] in flows[ip2id[dip]]:
                del flows[ip2id[dip]][item['uid']]
                flows[ip2id[dip]][item['uid'] + str(item['ts'])] = item
            else:
                flows[ip2id[dip]][item['uid']] = item

    id2ip = {}
    for ip in ip2id:
        if ip2id[ip] not in id2ip:
            id2ip[ip2id[ip]] = ip
        else:
            id2ip[ip2id[ip]] += ';' + ip

    for key in flows:
        if len(flows[key]) <= 1:
            continue
        flows[key] = sorted(flows[key].values(), key=lambda flow: flow['ts'])
        last_ts = flows[key][0]['ts']
        ip_key = '{}-{}'.format(id2ip[key], last_ts)
        if ip_key not in sequences:
            sequences[ip_key].append('S')
        for item in flows[key]:
            if item['ts'] - last_ts > time_delta:
                last_ts = item['ts']
                ip_key = '{}-{}'.format(id2ip[key], last_ts)
                if ip_key not in sequences:
                    sequences[ip_key].append('S')
            sequences[ip_key].append(flow2status(item))
            last_ts = item['ts']
    for key in sequences:
        sequences[key].append('E')
    return sequences
