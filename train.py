# -*- coding: utf-8 -*-
from __future__ import print_function
import json
import os
import math
import numpy as np
import pandas as pd
from sklearn.model_selection import ShuffleSplit

base_dir = '/home/work/m3f/ctu13'
all_data = {}


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


def read_data(target_label):
    df = pd.read_csv(os.path.join(base_dir, target_label + '.csv'))
    data = {}
    samples = set()

    for row in df.values:
        key = '{}-{}'.format(row[1], row[2])
        samples.add(row[1])
        if key not in data:
            data[key] = [key, 'S']
        status = flow2status(json.loads(row[3]))
        if status is not None:
            data[key].append(status)
    length = []
    max_seq_length = 102
    for key in data:
        if len(data[key]) > max_seq_length:
            data[key] = data[key][:max_seq_length]
        data[key].append('E')
        length.append(len(data[key]))
    return data


filenames = ['Zeus', 'Yakes', 'Artemis', 'Andromeda', 'Sality', 'CCleaner', 'MinerTrojan', 'OpenCandy']
for target_label in filenames:
    all_data[target_label] = read_data(target_label)

n_splits = 5
test_data = {}
train_data = {}
model = {}
for target_label in filenames:
    data = list(all_data[target_label].values())
    if len(data) == 0:
        continue
    data = np.array(data, dtype=object)
    ss = ShuffleSplit(n_splits=n_splits, test_size=0.3)
    test_data[target_label] = []
    train_data[target_label] = []
    model[target_label] = []
    for train_idx, test_idx in ss.split(data):
        X_train = data[train_idx]
        X_test = data[test_idx]
        test_data[target_label].append(X_test)
        train_data[target_label].append(X_train)
        trans_matrix = train(X_train)
        model[target_label].append(trans_matrix)

default_min_prob = 1e-100
default_label = 'benign'
y_true = []
y_pred = []
labels = test_data.keys()
flag = False
for target_label in labels:
    print('========={}==========='.format(target_label))
    for i in range(n_splits):
        result = {}
        result_seq = {}
        result_sample = {}
        label_min_prob = 1
        label_max_prob = -1
        for label in labels:
            result[label] = 0
            result_seq[label] = 0
            result_sample[label] = 0
        result[default_label] = 0
        result_seq[default_label] = 0
        result_sample[default_label] = 0
        for seq in test_data[target_label][i]:
            max_prob = -1
            max_prob_label = default_label
            for label in labels:
                trans_matrix = model[label][i]
                prob = get_prob(seq, trans_matrix)
                if prob < default_min_prob:
                    max_prob = max(max_prob, prob)
                    continue
                if prob > max_prob:
                    max_prob = prob
                    max_prob_label = label
            if max_prob < default_min_prob:
                max_prob_label = default_label
            if max_prob > 0:
                label_min_prob = min(label_min_prob, max_prob)
                label_max_prob = max(label_max_prob, max_prob)
            result[max_prob_label] += len(seq) - 3
            result_seq[max_prob_label] += 1
        print(np.sum(list(result_seq.values())),
              '%.2f' % (result_seq[target_label] / np.sum(list(result_seq.values())) * 100), result_seq)
