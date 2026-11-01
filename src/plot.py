"""
Extract results from flwr logs

Usage:
python3 extractResults.py id mode federation
mode - mode of the run: attack or no_attack
"""

import sys

import matplotlib.pyplot as plt
import pandas as pd

mode = sys.argv[1]


accuracy_per = pd.read_csv(f'./results/{mode}/client_acc.csv')
accuracy_avg = pd.read_csv(f'./results/{mode}/client_acc_avg.csv')

loss_per = pd.read_csv(f'./results/{mode}/client_loss.csv')
loss_avg = pd.read_csv(f'./results/{mode}/client_loss_avg.csv')

aP_transposed = accuracy_per.transpose()
aP_avg_transposed = accuracy_avg.transpose()
lP_transposed = loss_per.transpose()
lP_avg_transposed = loss_avg.transpose()

aP_transposed.plot(kind='line')
plt.xlabel('Round')
plt.ylabel('Accuracy')
plt.title('Accuracy over rounds per client')
plt.savefig(f"./results/{mode}/client_acc.png")

aP_avg_transposed.plot(kind='line')
plt.xlabel('Round')
plt.ylabel('Accuracy')
plt.title('Average Accuracy over rounds')
plt.savefig(f"./results/{mode}/client_acc_avg.png")

lP_transposed.plot(kind='line')
plt.xlabel('Round')
plt.ylabel('Loss')
plt.title('Loss over rounds per client')
plt.savefig(f"./results/{mode}/client_loss.png")

lP_avg_transposed.plot(kind='line')
plt.xlabel('Round')
plt.ylabel('Loss')
plt.title('Average Loss over rounds')
plt.savefig(f"./results/{mode}/client_loss_avg.png")

mode = "attack"
severity_acc = pd.read_csv(f'./results/{mode}/attack_acc.csv')
severity_loss = pd.read_csv(f'./results/{mode}/attack_loss.csv')

severity_loss.plot(x='Flipped', y='Loss', kind="line")
plt.xlabel('Flipping Percentage')
plt.ylabel('Loss')
plt.title('Loss with attack of various label flipping percentages')
plt.savefig(f"./results/{mode}/attack_loss.png")

severity_acc.plot(x='Flipped', y='Accuracy', kind='line')
plt.xlabel('Flipping Percentage')
plt.ylabel('Accuracy')
plt.title('Accuracy with attack of various label flipping percentages')
plt.savefig(f"./results/{mode}/attack_acc.png")
