"""
Extract results from flwr logs

Usage:
python3 extractResults.py id mode federation
id - ID of the run
mode - mode of the run: attack or no_attack
supergrid - optional, include supergrid if run on flower supergrid
"""


import csv
import sys
import os
import subprocess
from pathlib import Path


def get_csv(metric, dataset):
    avgs = []
    clients = {}
    rounds = ['id', 'isMalicious']
    for round in dataset:
        sum = 0
        num = 0
        for val in dataset[round]:
            sum += dataset[round][val]
            num += 1
            key = val
            if clients.get(key) is None:
                id = key.split("_")[1]
                isMalicious = "true" if bad_actors.get(int(id)) else "false"
                clients[key] = [int(id), isMalicious]
            clients[key].append(dataset[round][val])
        rounds.append(f'Round:{round}')
        avgs.append((sum / num))
    flip = ""
    if mode == 'attack':
        flip = f'_{flipped}'
    p = ''
    if pid:
        p = 'pid_'
    with(open(f'{dir}/{p}client_{metric}_avg{flip}.csv', 'w', encoding='utf-8')) as f:
        c = csv.writer(f, lineterminator='\n')
        c.writerow(rounds[2:])
        c.writerow(avgs)

    with(open(f'{dir}/{p}client_{metric}{flip}.csv', 'w', encoding='utf-8')) as f:
        c = csv.writer(f, lineterminator='\n')
        c.writerow(rounds)
        c.writerows(clients.values())




id = sys.argv[1]
dir = f'./results/{sys.argv[2]}'
mode = sys.argv[2]
pid_string = sys.argv[3].lower()
pid = True if pid_string == "true" else False
isSupergrid = "local"
if len(sys.argv) > 4:
    isSupergrid = sys.argv[4]
res = subprocess.run(['flwr', 'log', id, isSupergrid], capture_output=True, text=True, encoding='utf-8', errors='ignore')


f = open('flower_run.txt', 'w', encoding='utf-8')

lines = res.stdout.splitlines()

final = False
found_results = False
server_results = False
flipped = 0
global_acc = 0
global_loss = 0
bad_actors = {}
clients = 0
round_elim = []
r = 0 #round
for l in lines:
    if l.endswith("simulated SuperNodes)"):
        l = l.strip(" simulated SuperNodes)")
        ind = l.find("(")
        l = l[ind+1:]
        clients = int(l)
        for i in range(clients):
            round_elim.append(0)
        continue
    if pid and l.startswith("\x1b[36m(ClientAppActor pid=") and l.endswith("-"):
        l = l.split("\x1b[0m")
        l = l[1]
        l = l.strip("-")
        l = l.split(":")
        isMalicious =  True if l[1] == "MALICIOUS" else False
        bad_actors[int(l[0].lstrip())] = isMalicious
        continue
    if pid and l.startswith("---"):
        l = l.strip("-").strip()
        r = int(l[len(l)-1])
        continue
    if pid and l.startswith("[ANOMALY]"):
        l = l.lstrip("[ANOMALY]")
        l = l.split("|")
        l = l[0].strip()
        l = l.lstrip("Client ")
        l = int(l)
        round_elim[l] = r
        continue
    if l.startswith("Flipped"):
        l=l.split(":")
        flipped = int(l[1])
        continue
    if not l.startswith('[92mINFO [0m:'):
        continue
    l = l.strip("[92mINFO [0m")
    l = l.strip(":")
    l = l.strip()
    if l.startswith("Final"):
        final = True
        continue
    if l.startswith("└──> M"):
        l = l.split("{")
        l = l[1].strip("}")
        l = l.split(",")
        global_acc = float(l[0].split(":")[1].strip())
        global_loss = float(l[1].split(":")[1].strip())
        continue

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
    if len(l) == 0:
        continue
    if len(l) != 2:
        round = l[0].strip(":")
        prev_round = str(int(round) - 1)
        client_loss[round] = {}
        client_accuracy[round] = {}
        for i in range(clients):
            if round_elim[i] <= int(round) and round_elim[i] != 0:
                key = f'client_{i}_eval_acc'
                client_accuracy[round][key] = client_accuracy[prev_round][key]
                key = f'client_{i}_eval_loss'
                client_loss[round][key] = client_loss[prev_round][key]
        key = l[2]
        key = key.strip(":")
        key = key.strip("'")
        val = l[3]
        val = val.strip(",")
        val = val.strip("'")
        client_accuracy[round][key] = float(val)
        # print(round)
    else:
        if l[1].startswith('{}'):
            round = l[0].strip(":")
            prev_round = str(int(round) - 1)
            client_loss[round] = {}
            client_accuracy[round] = {}
            for i in range(clients):
                key = f'client_{i}_eval_acc'
                client_accuracy[round][key] = client_accuracy[prev_round][key]
                key = f'client_{i}_eval_loss'
                client_loss[round][key] = client_loss[prev_round][key]
            continue

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

clients_arr = []
for i in range(clients):
    clients_arr.append(f'Client {i}')
    if round_elim[i] == 0:
        round_elim[i] = int(round)

if pid:
    with(open(f'{dir}/pid_round_exit_{flipped}.csv', 'w', encoding='utf-8')) as f:
        c = csv.writer(f, lineterminator='\n')
        c.writerow(clients_arr)
        c.writerow(round_elim)

file = Path('flower_run.txt')
file.unlink(missing_ok=True)

get_csv("loss", client_loss)
get_csv("acc", client_accuracy)

dir = f'./results/attack/'
if pid:
    dir += "pid_"

if not os.path.exists(f'{dir}attack_acc.csv'):
    with(open(f'{dir}attack_acc.csv', 'a', encoding='utf-8')) as f:
        c = csv.writer(f, lineterminator='\n')
        c.writerow(["Flipped", "Accuracy"])
        c.writerow([flipped, global_acc])
    with(open(f'{dir}attack_loss.csv', 'a', encoding='utf-8')) as f:
        c = csv.writer(f, lineterminator='\n')
        c.writerow(["Flipped", "Loss"])
        c.writerow([flipped, global_loss])
else:
    with(open(f'{dir}attack_acc.csv', 'a', encoding='utf-8')) as f:
        c = csv.writer(f, lineterminator='\n')
        c.writerow([flipped, global_acc])
    with(open(f'{dir}attack_loss.csv', 'a', encoding='utf-8')) as f:
        c = csv.writer(f, lineterminator='\n')
        c.writerow([flipped, global_loss])
