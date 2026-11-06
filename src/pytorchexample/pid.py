from typing import Iterable

from flwr.app import MetricRecord, RecordDict
from collections import defaultdict
import numpy as np
import flwr.server
from flwr.common import (
    parameters_to_ndarrays,
    ndarrays_to_parameters,
)
from flwr.app import (ArrayRecord,
    ConfigRecord,
    Message,
    MetricRecord,
    )
from flwr.serverapp import Grid
from flwr.serverapp.strategy.strategy_utils import aggregate_arrayrecords


class PIDAnomalyDetector:
    """PID-based detector for abnormal client model updates."""

    def __init__(
        self,
        kp=1.0,
        ki=0.05,
        kd=0.1,
        threshold=0.4,
    ):
        self.kp = kp
        self.ki = ki
        self.kd = kd
        self.threshold = threshold

        # PID state maintained independently for each client
        self.integral = defaultdict(float)
        self.previous_dist = defaultdict(float)


    def calculate_score(self, client_id, dist):
        """Calculate the PID score."""

        # Proportional component
        p = self.kp * dist

        # Integral component
        self.integral[client_id] += dist
        i = self.ki * self.integral[client_id]

        # Derivative component
        derivative = (
                dist - self.previous_dist[client_id]
        )
        d = self.kd * derivative

        self.previous_dist[client_id] = dist

        return abs(p + i + d)

    def is_anomaly(self, client_id, error):
        """Check if the client is anomalous."""
        score = self.calculate_score(client_id, error) #get score

        return score > self.threshold, score # compare to threshold


class PIDFedAvg(flwr.serverapp.strategy.FedAvg):
    """FedAvg with PID-based client anomaly detection."""

    def __init__(
            self,
            pid_threshold=0.4,
            kp=1.0,
            ki=0.05,
            kd=0.5,
            **kwargs,
    ):
        super().__init__(**kwargs)

        self.global_parameters = None

        self.malicious = set()

        self.client_map = {}

        self.detector = PIDAnomalyDetector(
            kp=kp,
            ki=ki,
            kd=kd,
            threshold=pid_threshold,
        )

    def configure_train(
            self,
            server_round: int,
            arrays: ArrayRecord,
            config: ConfigRecord,
            grid: Grid,
    ) -> Iterable[Message]:

        print(
            f"\n[PID] Configuring training for round {server_round}"
        )

        # Save a copy of the global model before clients train
        self.global_parameters = [
            np.array(arr, copy=True)
            for arr in arrays.to_numpy_ndarrays()
        ]

        # Use Flower's normal client selection and distribution
        messages = super().configure_train(
            server_round,
            arrays,
            config,
            grid,
        )

        allowed_messages = [
            msg for msg in messages
            if msg.metadata.dst_node_id
               not in self.malicious
        ]

        return allowed_messages


    def aggregate_train(self, server_round, replies):
        print(f"\n--- Round {server_round} ---")
        replies = [
            reply for reply in replies
            if reply.metadata.src_node_id
               not in self.malicious
        ]

        # Obtain current global parameters
        global_parameters = self.global_parameters
        replies = list(replies)
        if not replies:
            print("[PID] No client replies received.")
            return None, None

        # Calculate each client's update magnitude
        client_distances = {}
        client_msgs = {}

        i = 0
        client_params = {}
        for reply in replies:

            if reply.has_error():
                print(
                    f"[ERROR] Node {reply.metadata.src_node_id} "
                    "returned an error."
                )
                continue

            client_id = reply.metadata.src_node_id
            if server_round == 1:
                self.client_map[client_id] = i
                i+=1

            try:
                client_parameters = (
                    reply.content[self.arrayrecord_key]
                    .to_numpy_ndarrays()
                )
                client_msgs[client_id] = reply
                client_params[client_id] = client_parameters

            except (KeyError, ValueError) as exc:
                print(
                    f"[ERROR] Could not inspect node "
                    f"{client_id}: {exc}"
                )



        # Calculate average parameters across all clients
        average_parameters = []

        for layer_idx in range(
                len(next(iter(client_params.values())))
        ):
            layer_average = np.median(
                [
                    params[layer_idx]
                    for params in client_params.values()
                ],
                axis=0,
            )

            average_parameters.append(layer_average)


        for client_id, client_params in client_params.items():

            squared_distance = 0.0
            total_parameters = 0

            for client_layer, average_layer in zip(
                    client_params,
                    average_parameters,
            ):
                difference = client_layer - average_layer

                squared_distance += np.sum(
                    np.square(difference)
                )

                total_parameters += client_layer.size

            distance = np.sqrt(
                squared_distance / total_parameters
            )

            client_distances[client_id] = distance

            print(
                f"[CLIENT] Node {self.client_map[client_id]} "
                f"distance from average: {distance:.6f}"
            )



        # Mean deviation acts as the expected behavior
        expected_distance = np.median(
            list(client_distances.values())
        )

        accepted_replies = []
        anomaly_count = 0

        # Evaluate each client using its PID controller
        for client_id, distance in client_distances.items():

            distance = client_distances[client_id]

            error = distance - expected_distance

            error /= max(list(client_distances.values()))

            anomaly, score = self.detector.is_anomaly(
                client_id,
                error,
            )

            if anomaly and server_round > 1:
                self.malicious.add(client_id)
                anomaly_count += 1
                print(
                    f"[ANOMALY] Client {self.client_map[client_id]} "
                    f"| Score: {score:.6f}"
                )
            else:
                print(
                    f"[NORMAL] Client {self.client_map[client_id]} "
                    f"| Score: {score:.6f}"
                )
                accepted_replies.append(
                    client_msgs[client_id]
                )

        print(
            f"Detected {anomaly_count} anomalous "
            f"clients out of {len(client_distances)}"
        )

        # Aggregate only accepted client updates
        if not accepted_replies:
            print("No clients accepted. Skipping aggregation.")
            return None, {
                "anomalies_detected": anomaly_count,
                "accepted_clients": 0,
            }

        aggregated_arrays, aggregated_metrics = (
            super().aggregate_train(
                server_round,
                accepted_replies,
            )
        )

        if aggregated_metrics is None:
            aggregated_metrics = MetricRecord()

        aggregated_metrics["pid_anomalies_detected"] = (
            anomaly_count
        )

        aggregated_metrics["pid_clients_accepted"] = (
            len(accepted_replies)
        )

        print(
            f"[PID] Round {server_round} aggregation complete."
        )

        return aggregated_arrays, aggregated_metrics

    def configure_evaluate(
            self, server_round, arrays, config, grid
    ):
        messages = super().configure_evaluate(
            server_round, arrays, config, grid
        )

        allowed_messages = [
            msg for msg in messages
            if msg.metadata.dst_node_id
               not in self.malicious
        ]

        print(
            f"[PID] Evaluation round {server_round}: "
            f"{len(allowed_messages)} eligible nodes"
        )

        return allowed_messages

    def aggregate_evaluate(self, server_round, replies):

        replies = [
            reply for reply in replies
            if reply.metadata.src_node_id
               not in self.malicious
        ]

        print(
            f"[PID] Aggregating evaluation results "
            f"from {len(replies)} eligible nodes"
        )

        unaggregated_bundle = MetricRecord()
        # with(open(f"./results/no_attack/aggregated.txt", "a")) as file:
        for reply in replies:
            client_id = reply.metadata.src_node_id
            record = reply.content
            for metric_record in record.metric_records.values():
                for key, value in metric_record.items():
                    if key == "num-examples":
                        continue
                    # Group by client index or unique client tags
                    unique_key = f"client_{self.client_map[client_id]}_{key}"
                    unaggregated_bundle[unique_key] = value
                    # file.write(f"{unique_key}: {value}\n")

        return unaggregated_bundle