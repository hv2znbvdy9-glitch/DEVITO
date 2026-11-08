"""Tests for the AVA neuron-model reference helpers."""

import pytest

from ava.neuron_models import (
    axial_current,
    compartment_voltage_derivative,
    conductance_current,
    euler_voltage_step,
    get_hay_l5b_reference_spec,
)


def test_hay_reference_is_explicitly_not_full_simulation():
    spec = get_hay_l5b_reference_spec()
    assert "Hay et al." in spec.name
    assert spec.simulation_ready is False
    assert "NEURON-compatible simulator" in spec.required_runtime_assets
    assert "full Hay-model simulation" in spec.limitation


def test_conductance_current_uses_outward_positive_sign():
    assert conductance_current(0.12, -20.0, 50.0) == pytest.approx(-8.4)


def test_axial_current_flows_toward_local_compartment():
    assert axial_current(0.1, -50.0, -65.0) == pytest.approx(1.5)


def test_compartment_voltage_derivative():
    dv_dt = compartment_voltage_derivative(
        capacitance=1.0,
        applied_current=2.0,
        ionic_currents=[0.5],
        axial_currents=[1.0],
    )
    assert dv_dt == pytest.approx(2.5)


def test_euler_voltage_step():
    assert euler_voltage_step(-65.0, 0.01, 2.5) == pytest.approx(-64.975)


@pytest.mark.parametrize(
    ("fn", "args"),
    [
        (conductance_current, (-0.1, -65.0, -70.0)),
        (axial_current, (-0.1, -60.0, -65.0)),
        (compartment_voltage_derivative, (0.0, 0.0, [], [])),
        (euler_voltage_step, (-65.0, 0.0, 1.0)),
    ],
)
def test_invalid_parameters_raise(fn, args):
    with pytest.raises(ValueError):
        fn(*args)
