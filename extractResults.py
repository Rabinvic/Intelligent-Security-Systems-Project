"""
Extract results from flwr logs

Usage:
python3 extractResults.py id mode federation
id - ID of the run
mode - mode of the run: attack or no_attack
"""


import csv
import sys
import os
import subprocess
from pathlib import Path


def get_csv(metric, dataset):
    avgs = []
    clients = {}
    for round in dataset:
        sum = 0
        num = 0
        for val in dataset[round]:
            sum += dataset[round][val]
            num += 1
            key = val
            if clients.get(key) is None:
                clients[key] = []
            clients[key].append(dataset[round][val])

        avgs.append((sum / num))

    with(open(f'{dir}/client_{metric}_avg.csv', 'w', encoding='utf-8')) as f:
        c = csv.writer(f, lineterminator='\n')
        c.writerow(avgs)

    with(open(f'{dir}/client_{metric}.csv', 'w', encoding='utf-8')) as f:
        c = csv.writer(f, lineterminator='\n')
        c.writerows(clients.values())




id = sys.argv[1]
dir = f'.\\results\\{sys.argv[2]}'
mode = sys.argv[2]


res = subprocess.run(['flwr', 'log', id, 'supergrid'], capture_output=True, text=True, encoding='utf-8', errors='ignore')

f = open('flower_run.txt', 'w', encoding='utf-8')

lines = res.stdout.splitlines()

found_results = False

for l in lines:
    if not l.startswith('[92mINFO [0m:'):
        continue
    l = l.strip("[92mINFO [0m")
    l = l.strip(":")
    l = l.strip()
    if l.startswith("Aggregated ClientApp-side Evaluate Metrics"):
        found_results = True
        continue
    if not found_results:
        continue
    if l.startswith("ServerApp-side Evaluate Metrics"):
        found_results = False
        continue
    if l.startswith("{"):
        l = l.strip("{")
    f.write(f'{l}\n')

f.close()

f = open('flower_run.txt', 'r', encoding='utf-8')
lines = f.readlines()

client_loss = {}
client_accuracy = {}

round = ""
for l in lines:
    l = l.split()
    #print(l)
    if len(l) == 0:
        continue
    if len(l) != 2:
        round = l[0].strip(":")
        client_loss[round] = {}
        client_accuracy[round] = {}
        key = l[2]
        key = key.strip(":")
        key = key.strip("'")
        val = l[3]
        val = val.strip(",")
        val = val.strip("'")
        client_accuracy[round][key] = float(val)
        # print(round)
    else:
        key = l[0]
        key = key.strip(":")
        key = key.strip("'")
        val = l[1]
        val = val.strip(",")
        val = val.strip("}")
        val = val.strip("'")
        if key.endswith("acc"):
            client_accuracy[round][key] = float(val)
        else:
            client_loss[round][key] = float(val)

f.close()

file = Path('flower_run.txt')
file.unlink(missing_ok=True)

get_csv("loss", client_loss)
get_csv("acc", client_accuracy)
