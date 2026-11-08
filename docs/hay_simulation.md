# Hay et al. 2011 simulation

`ava.hay_simulation` runs a local, read-only analysis using the
ModelDB accession **139653**, “L5b PC model constrained for BAC firing and
perisomatic current step firing” (Hay et al., 2011).

## Installation

Install NEURON separately from AVA, then compile the model mechanisms in the
extracted ModelDB directory:

```bash
python -m pip install neuron
cd /path/to/139653
nrnivmodl mod
```

The extracted archive must contain `models/L5PCtemplate.hoc`,
`models/L5PCbiophys3.hoc`, and `morphologies/cell1.asc`.

## Run

```bash
python -m ava.hay_simulation \
  --model-dir /path/to/139653 \
  --output /path/to/results/hay.csv
```

The default simulation runs for 100 ms with a 0.793 nA soma pulse from 20 ms
to 60 ms and writes `time_ms`, `soma_mV`, and `apical_mV` columns. Parameters
can be adjusted with `--duration-ms`, `--dt-ms`, `--pulse-start-ms`,
`--pulse-duration-ms`, and `--pulse-amp-na`.

The integration test uses `AVA_HAY_MODEL_DIR` and is skipped when no extracted
ModelDB archive is configured:

```bash
AVA_HAY_MODEL_DIR=/path/to/139653 python -m pytest tests/test_hay_simulation.py
```
