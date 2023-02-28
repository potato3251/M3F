# -*- coding: utf-8 -*-
from __future__ import print_function
import os
import json
import re
import numpy as np
import pandas as pd

base_dir = '/home/work/m3f/ctu13/'
ignore_domain = {'time.windows.com', 'www.download.windowsupdate.com',
                 'windowsupdate.microsoft.com', }

filenames = ['Zeus', 'Yakes', 'Artemis', 'Andromeda',
             'Sality', 'CCleaner', 'MinerTrojan', 'OpenCandy']
time_delta = 120
for target_label in filenames:
    data = {'path': [], 'ip': [], 'flow': []}

    filename = os.path.join(base_dir, target_label)

    full_path = filename + '.conn.log'
    if not os.path.exists(full_path):
        continue
    dns_full_path = filename + '.dns.log'
    fr = open(dns_full_path)
    dns_lines = fr.readlines()
    fr.close()
    dns_flows = {}
    ip2id = {}
    ignore_ip = set()
    domain2id = {}
    for line in dns_lines:
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

    http_full_path = filename + '.http.log'
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
    cnt = 0
    for line in conn_lines:
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

    max_cnt = 2
    max_cnt_key = ''
    length = {}
    for key in flows:
        if len(flows[key]) <= 1:
            continue
        if max_cnt < len(flows[key]):
            max_cnt = len(flows[key])
            max_cnt_key = key
        flows[key] = sorted(flows[key].values(), key=lambda flow: flow['ts'])
        last_ts = flows[key][0]['ts']
        split_by_time = {}
        split_key = '{}-{}'.format(key, last_ts)
        split_by_time[split_key] = []

        last_ts = flows[key][0]['ts']
        ip_key = '{}-{}'.format(id2ip[key], last_ts)
        for item in flows[key]:
            if item['ts'] - last_ts > time_delta:
                last_ts = item['ts']
                ip_key = '{}-{}'.format(id2ip[key], last_ts)
            data['path'].append(filename)
            data['ip'].append(ip_key)
            data['flow'].append(json.dumps(item))
            if ip_key not in length:
                length[ip_key] = 0
            length[ip_key] += 1
            last_ts = item['ts']
    length = np.array(list(length.values()))
    print('mean: ', np.mean(length), 'min: ', np.min(length),
          'max: ', np.max(length), 'total: ', len(length), 'seq: ', np.sum(length > 1))
    df = pd.DataFrame(data)
    df.to_csv('{}/{}.csv'.format(base_dir, target_label), index_label='id')
    print(target_label, len(data['ip']), len(conn_lines), time_delta)
