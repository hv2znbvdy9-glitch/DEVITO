"""Run a small, reproducible current-step simulation of Hay et al. (2011).

The NEURON dependency is imported only when :func:`run_hay_simulation` is
called, so the rest of AVA remains usable without NEURON installed.
"""

from __future__ import annotations

import argparse
import csv
import os
from pathlib import Path
from typing import Any, Iterable, Union


MODEL_ID = "139653"


def _find_model_file(model_dir: Path, name: str) -> Path:
    matches = sorted(model_dir.rglob(name))
    if not matches:
        raise FileNotFoundError(f"Hay model file not found below {model_dir}: {name}")
    return matches[0]


def _load_mechanisms(model_dir: Path) -> None:
    from neuron import load_mechanisms

    if not load_mechanisms(str(model_dir)):
        raise RuntimeError(f"Compile the Hay mechanisms in {model_dir} with nrnivmodl mod")


def _load_hay_cell(h: Any, model_dir: Path) -> Any:
    """Load the ModelDB 139653 L5PC template and return one cell instance."""
    template = _find_model_file(model_dir, "L5PCtemplate.hoc")
    biophysics = _find_model_file(model_dir, "L5PCbiophys3.hoc")
    morphology = _find_model_file(model_dir, "cell1.asc")

    _load_mechanisms(model_dir)
    h.load_file("stdrun.hoc")
    h.load_file("import3d.hoc")
    h.load_file(str(biophysics))
    h.load_file(str(template))
    return h.L5PCtemplate(str(morphology))


def _first_section(cell: Any, attribute: str) -> Any:
    sections = getattr(cell, attribute, None)
    if sections is None:
        raise RuntimeError(f"Hay cell does not expose a {attribute} section list")
    try:
        return sections[0]
    except (IndexError, TypeError):
        raise RuntimeError(f"Hay cell has no {attribute} sections") from None


def _values(vector: Any) -> Iterable[float]:
    return (float(vector[index]) for index in range(int(vector.size())))


def run_hay_simulation(
    model_dir: Union[str, os.PathLike],
    output: Union[str, os.PathLike],
    *,
    duration_ms: float = 100.0,
    dt_ms: float = 0.025,
    pulse_start_ms: float = 20.0,
    pulse_duration_ms: float = 40.0,
    pulse_amp_nA: float = 0.793,
) -> Path:
    """Run a soma current pulse and write soma/apical voltages to ``output``.

    ``model_dir`` must be an extracted ModelDB 139653 archive, with the
    ``models/L5PCtemplate.hoc``, ``models/L5PCbiophys3.hoc`` and
    ``morphologies/cell1.asc`` files available below it.
    """
    model_path = Path(model_dir).expanduser().resolve()
    output_path = Path(output).expanduser().resolve()
    if not model_path.is_dir():
        raise NotADirectoryError(f"Model directory does not exist: {model_path}")
    if duration_ms <= 0 or dt_ms <= 0:
        raise ValueError("duration_ms and dt_ms must be positive")
    if pulse_start_ms < 0 or pulse_duration_ms < 0:
        raise ValueError("pulse_start_ms and pulse_duration_ms cannot be negative")
    if pulse_start_ms + pulse_duration_ms > duration_ms:
        raise ValueError("current pulse must fit within duration_ms")

    try:
        from neuron import h
    except ImportError as exc:
        raise RuntimeError(
            "NEURON is required for Hay simulation; install it with `pip install neuron`"
        ) from exc

    previous_cwd = Path.cwd()
    try:
        os.chdir(model_path)
        cell = _load_hay_cell(h, model_path)
        soma = _first_section(cell, "soma")
        apical = _first_section(cell, "apic")

        clamp = h.IClamp(soma(0.5))
        clamp.delay = pulse_start_ms
        clamp.dur = pulse_duration_ms
        clamp.amp = pulse_amp_nA

        times = h.Vector()
        soma_voltage = h.Vector()
        apical_voltage = h.Vector()
        times.record(h._ref_t)
        soma_voltage.record(soma(0.5)._ref_v)
        apical_voltage.record(apical(0.5)._ref_v)

        h.CVode().active(0)
        h.celsius = 34.0
        h.dt = dt_ms
        h.finitialize(-80.0)
        h.continuerun(duration_ms)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(("time_ms", "soma_mV", "apical_mV"))
            writer.writerows(zip(_values(times), _values(soma_voltage), _values(apical_voltage)))
    finally:
        os.chdir(previous_cwd)

    return output_path


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--duration-ms", type=float, default=100.0)
    parser.add_argument("--dt-ms", type=float, default=0.025)
    parser.add_argument("--pulse-start-ms", type=float, default=20.0)
    parser.add_argument("--pulse-duration-ms", type=float, default=40.0)
    parser.add_argument("--pulse-amp-na", type=float, default=0.793)
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    result = run_hay_simulation(
        args.model_dir,
        args.output,
        duration_ms=args.duration_ms,
        dt_ms=args.dt_ms,
        pulse_start_ms=args.pulse_start_ms,
        pulse_duration_ms=args.pulse_duration_ms,
        pulse_amp_nA=args.pulse_amp_na,
    )
    print(result)


if __name__ == "__main__":
    main()
