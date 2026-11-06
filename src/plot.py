"""
Extract results from flwr logs

Usage:
python3 extractResults.py id mode federation
mode - mode of the run: attack or no_attack
pid - boolean representing if pid was used
"""

import sys

import matplotlib.pyplot as plt
import pandas as pd
from pathlib import Path


def plot_attack_severity(file, metric):
    severity= pd.read_csv(file)
    label = 'Accuracy' if metric == "acc" else 'Loss'
    severity.plot(x='Flipped', y=label, kind='line')
    plt.xlabel('Flipping Percentage')
    plt.ylabel(label)
    plt.title(f'{label} with attack of various label flipping percentages')
    plt.legend(fontsize='small')
    plotName = file.name.replace(".csv", ".png")
    plt.savefig(f"./results/{mode}/{plotName}")
    plt.close()

def plot_client_metric(file, metric, averaged, flip):
    data = pd.read_csv(file,usecols=lambda column: column not in ["isMalicious"], index_col="id") if not averaged else (
        pd.read_csv(file, usecols=lambda column: column not in ["isMalicious"]))
    data_transposed = data.transpose()
    label = "Accuracy" if metric == "acc" else "Loss"
    title = f"Average {label} over rounds, Flip Rate {flip}" if averaged else f"{label} over rounds per client, Flip Rate {flip}"
    data_transposed.plot(kind='line')
    plt.xlabel('Round')
    plt.ylabel(label)
    plt.title(title)
    plt.legend(fontsize='small')
    plotName = file.name.replace(".csv", ".png")
    plt.savefig(f"./results/{mode}/{plotName}")
    plt.close()

def plot_drop(file, flip):
    data = pd.read_csv(file)
    data_transposed = data.transpose()
    data_transposed.plot(kind='bar')
    plt.title(f'Round In Which Client was dropped, Flip Rate:{flip}', fontsize=14, fontweight='bold')
    plt.xlabel('Client', fontsize=12)
    plt.ylabel('Round', fontsize=12)
    plt.gcf().subplots_adjust(bottom=0.2)
    plotName = file.name.replace(".csv", ".png")
    plt.savefig(f"./results/{mode}/{plotName}")
    plt.close()



mode = sys.argv[1]
pid_string = sys.argv[2].lower()
pid = True if pid_string == "true" else False


directory = Path(f"./results/{mode}/")

files = []
for f in directory.iterdir():
    if not f.name.endswith(".csv"):
        continue
    if pid and f.name.startswith("pid"):
        files.append(f)
    if not pid and not f.name.startswith("pid"):
        files.append(f)

for f in files:
    file_name = f.name
    file_name = file_name.replace(".csv", "")
    if pid:
        file_name = file_name.lstrip("pid_")
    if file_name.startswith("attack"):
        if file_name.endswith("acc"):
            plot_attack_severity(f, "acc")
        else:
            plot_attack_severity(f, "loss")
        continue
    if file_name.startswith("round"):
        flip = file_name.split("_")[2]
        plot_drop(f,flip)
        continue
    file_name = file_name.lstrip("client_")
    params = file_name.split("_")
    metric = params[0]
    fliprate = params[len(params) - 1]
    averaged = False if len(params) == 2 else True
    plot_client_metric(f, metric, averaged, fliprate)
