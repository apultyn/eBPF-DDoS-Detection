# In-Kernel DDoS Detection with eBPF/XDP

A DDoS detection research project comparing user-space packet processing with
eBPF/XDP processing. Both variants use HeavyKeeper to identify high-volume sources
and IQR-based thresholds to detect anomalies, with tools for evaluating detection
quality and resource usage on CIC-DDoS2019 traffic.

The kernel variant processes and counts packets in XDP; a Go process reads the
results and evaluates detection windows in user space.

## Repository Layout

| Directory | Purpose |
|---|---|
| `kernelspace/` | XDP packet processing and Go detector |
| `userspace/` | Reference detector supporting PCAP files and live capture |
| `analysis/` | Ground-truth preparation, evaluation, and comparison |
| `scripts/` | Experiment and measurement tools |

## Quick Start

With Go 1.25.4 or later installed, run the user-space detector on an existing PCAP
file from the repository root:

```sh
go run ./userspace/cmd/detector -pcap path/to/trace.pcap -out results/demo
```

Replace `path/to/trace.pcap` with your capture file. The command writes
`windows.csv`, `ips.csv`, and `run.json` under `results/demo/`.

For live capture and XDP setup, see the
[live evaluation guide](docs/live-evaluation.md), including its requirements
for Linux and additional tools.

## Documentation

- [Evaluation guide](analysis/GUIDE.md)
- [Live experiments](docs/live-evaluation.md)
- [Measurement scripts](scripts/README.md)
- [Project report](project-report.pdf)

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for repository setup, branch policy,
commit conventions, and pull request requirements.

## Authors

- Tabita Tengblad - <tabita.tengblad@gmail.com>
- Ida Åberg - <idaaberg0310@gmail.com>
- Andrzej Pultyn - <jedrek.pultyn@gmail.com>
- Mårten Granath - <marten.gth@gmail.com>
