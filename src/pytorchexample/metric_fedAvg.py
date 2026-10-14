import json

from flwr.app import MetricRecord, RecordDict
from flwr.serverapp.strategy import FedAvg


def extract_nonaggregated_metrics(
        records: list[RecordDict], weighting_metric_name: str

) -> MetricRecord:
    """
    Extracts individual raw metrics from all SuperGrid nodes.
    """
    unaggregated_bundle = MetricRecord()
    # with(open(f"./results/no_attack/aggregated.txt", "a")) as file:
    for idx, record in enumerate(records):
        for metric_record in record.metric_records.values():
            for key, value in metric_record.items():
                if key == "num-examples":
                    continue
                # Group by client index or unique client tags
                unique_key = f"client_{idx}_{key}"
                unaggregated_bundle[unique_key] = value
                # file.write(f"{unique_key}: {value}\n")


    return unaggregated_bundle
