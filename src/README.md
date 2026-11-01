# Federated Learning with PyTorch and Flower to demonstrate Model Poisoning

This an adaptation of the introductory example to Flower using PyTorch to study data poisoning attacks in federated learning.

Written by: Victor Rabinovich vmr8854@rit.edu

## Train Models

To run the federated learning without model poisoning ```flwr run ./src/ --stream``` suffices. Otherwise you must modify the run config as follows

```bash
flwr run ./src --run-config "poison=true flipped=[int] malicious=[int]" --stream
```
Where flipped and malicious are the percentage of label switching and malicious actors respectively.

## Gather Data
To gather data you will run the extractResults.py script, this script takes a flower run id and uses this to extract the logs to make csv files for the metrics

You must ensure your terminal is set to receive UTF8 python results or else the script can not read the Flower log data/
This can be done in PowerShell with 
```shell
$env:PYTHONUTF8=1
```
### Usage

```bash
py ./src/extractResults.py [id] [mode] [Optional: supergrid]
```
id: The id of the flower run can be found at the top of the stream from the run, or if on Flower Supergrid listed as Run ID
mode: ```attack``` or ```no_attack``` based on if there was an attack simulated for that run or not
supergrid: Optional flag if run occurred on Flower Supergrid

>The final global metrics for different severities of flipping attacks gets appended each time the script is run into its own
> csv file. However only the individual client metrics of the last attack run gets saved for the plots.


## Plotting Data
After running extractResults.py run plot.py to plot the results and save the graphs

```bash
py ./src/plot.py [mode]
```
mode: ```attack``` or ```no_attack``` based on folder to extract data from
