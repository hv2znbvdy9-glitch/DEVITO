#!/usr/bin/env python3
"""Small, dependency-free Lindblad simulation for a single open qubit.

This is a classical numerical integration of the Lindblad master equation,
not a claim that a computer simulation is itself a quantum system.
"""
from __future__ import annotations

import argparse
import json
import math
from typing import List, Sequence, Tuple

Matrix = Tuple[Tuple[complex, complex], Tuple[complex, complex]]
TimedState = Tuple[float, Matrix]

IDENTITY: Matrix = ((1.0 + 0.0j, 0.0j), (0.0j, 1.0 + 0.0j))
SIGMA_X: Matrix = ((0.0j, 1.0 + 0.0j), (1.0 + 0.0j, 0.0j))
SIGMA_Y: Matrix = ((0.0j, -1.0j), (1.0j, 0.0j))
SIGMA_Z: Matrix = ((1.0 + 0.0j, 0.0j), (0.0j, -1.0 + 0.0j))
LOWERING: Matrix = ((0.0j, 1.0 + 0.0j), (0.0j, 0.0j))  # |0><1|
EXCITED_STATE: Matrix = ((0.0j, 0.0j), (0.0j, 1.0 + 0.0j))
PLUS_STATE: Matrix = ((0.5 + 0.0j, 0.5 + 0.0j), (0.5 + 0.0j, 0.5 + 0.0j))


def add(left: Matrix, right: Matrix) -> Matrix:
    return tuple(
        tuple(left[row][col] + right[row][col] for col in range(2))
        for row in range(2)
    )  # type: ignore[return-value]


def subtract(left: Matrix, right: Matrix) -> Matrix:
    return tuple(
        tuple(left[row][col] - right[row][col] for col in range(2))
        for row in range(2)
    )  # type: ignore[return-value]


def scale(factor: complex, matrix: Matrix) -> Matrix:
    return tuple(
        tuple(factor * matrix[row][col] for col in range(2))
        for row in range(2)
    )  # type: ignore[return-value]


def multiply(left: Matrix, right: Matrix) -> Matrix:
    return tuple(
        tuple(
            sum(left[row][inner] * right[inner][col] for inner in range(2))
            for col in range(2)
        )
        for row in range(2)
    )  # type: ignore[return-value]


def dagger(matrix: Matrix) -> Matrix:
    return tuple(
        tuple(matrix[col][row].conjugate() for col in range(2))
        for row in range(2)
    )  # type: ignore[return-value]


def trace(matrix: Matrix) -> complex:
    return matrix[0][0] + matrix[1][1]


def commutator(left: Matrix, right: Matrix) -> Matrix:
    return subtract(multiply(left, right), multiply(right, left))


def lindblad_rhs(
    density: Matrix, hamiltonian: Matrix, jump_operators: Sequence[Matrix]
) -> Matrix:
    """Return d(rho)/dt = -i[H,rho] + sum_j D[L_j](rho), with hbar = 1."""
    derivative = scale(-1.0j, commutator(hamiltonian, density))
    for operator in jump_operators:
        adjoint = dagger(operator)
        rate_operator = multiply(adjoint, operator)
        jump = multiply(multiply(operator, density), adjoint)
        anticommutator = add(
            multiply(rate_operator, density), multiply(density, rate_operator)
        )
        contribution = subtract(jump, scale(0.5, anticommutator))
        derivative = add(derivative, contribution)
    return derivative


def _combine(state: Matrix, terms: Sequence[Tuple[float, Matrix]]) -> Matrix:
    result = state
    for factor, term in terms:
        result = add(result, scale(factor, term))
    return result


def _rk4_step(
    state: Matrix,
    step_size: float,
    hamiltonian: Matrix,
    jump_operators: Sequence[Matrix],
) -> Matrix:
    rhs = lambda value: lindblad_rhs(value, hamiltonian, jump_operators)
    k1 = rhs(state)
    k2 = rhs(_combine(state, ((step_size / 2.0, k1),)))
    k3 = rhs(_combine(state, ((step_size / 2.0, k2),)))
    k4 = rhs(_combine(state, ((step_size, k3),)))
    return _combine(
        state,
        (
            (step_size / 6.0, k1),
            (step_size / 3.0, k2),
            (step_size / 3.0, k3),
            (step_size / 6.0, k4),
        ),
    )


def evolve(
    initial_state: Matrix,
    hamiltonian: Matrix,
    jump_operators: Sequence[Matrix] = (),
    *,
    dt: float = 0.005,
    steps: int = 400,
) -> List[TimedState]:
    """Integrate a qubit trajectory with fixed-step fourth-order Runge-Kutta.

    Returns t=0 and every subsequent integration step. Results are approximate;
    reduce dt to test convergence. States are not projected back onto the
    physical-state set after each step.
    """
    if not math.isfinite(dt) or dt <= 0.0:
        raise ValueError("dt must be a finite positive number")
    if isinstance(steps, bool) or not isinstance(steps, int) or steps < 0:
        raise ValueError("steps must be a non-negative integer")
    if len(initial_state) != 2 or any(len(row) != 2 for row in initial_state):
        raise ValueError("initial_state must be a 2x2 matrix")
    if len(hamiltonian) != 2 or any(len(row) != 2 for row in hamiltonian):
        raise ValueError("hamiltonian must be a 2x2 matrix")

    trajectory: List[TimedState] = [(0.0, initial_state)]
    state = initial_state
    for index in range(steps):
        state = _rk4_step(state, dt, hamiltonian, jump_operators)
        trajectory.append(((index + 1) * dt, state))
    return trajectory


def make_operators(
    omega: float, gamma_relaxation: float, gamma_dephasing: float
) -> Tuple[Matrix, Tuple[Matrix, ...]]:
    """Build H=(omega/2) sigma_z, amplitude damping, and pure dephasing.

    gamma_relaxation sets the |1> -> |0> population-decay rate.
    gamma_dephasing is the additional off-diagonal decay rate. Hbar=1.
    """
    values = (omega, gamma_relaxation, gamma_dephasing)
    if not all(math.isfinite(value) for value in values):
        raise ValueError("omega and rates must be finite")
    if gamma_relaxation < 0.0 or gamma_dephasing < 0.0:
        raise ValueError("dissipation rates must be non-negative")

    hamiltonian = scale(omega / 2.0, SIGMA_Z)
    jumps: List[Matrix] = []
    if gamma_relaxation > 0.0:
        jumps.append(scale(math.sqrt(gamma_relaxation), LOWERING))
    if gamma_dephasing > 0.0:
        jumps.append(scale(math.sqrt(gamma_dephasing / 2.0), SIGMA_Z))
    return hamiltonian, tuple(jumps)


def bloch_vector(density: Matrix) -> Tuple[float, float, float]:
    """Return (x, y, z) for rho=(I+x*sigma_x+y*sigma_y+z*sigma_z)/2."""
    off_diagonal = density[0][1]
    return (
        2.0 * off_diagonal.real,
        -2.0 * off_diagonal.imag,
        (density[0][0] - density[1][1]).real,
    )


def purity(density: Matrix) -> float:
    """Return Tr(rho^2), up to floating-point rounding."""
    return trace(multiply(density, density)).real


def hermiticity_error(density: Matrix) -> float:
    """Return the largest element-wise difference from the Hermitian adjoint."""
    adjoint = dagger(density)
    return max(
        abs(density[row][col] - adjoint[row][col])
        for row in range(2)
        for col in range(2)
    )


def is_density_matrix(density: Matrix, tolerance: float = 1e-9) -> bool:
    """Check trace one, Hermiticity, and positivity for a 2x2 density matrix."""
    if tolerance < 0.0 or not math.isfinite(tolerance):
        raise ValueError("tolerance must be finite and non-negative")
    if hermiticity_error(density) > tolerance:
        return False
    density_trace = trace(density)
    if abs(density_trace.imag) > tolerance or abs(density_trace.real - 1.0) > tolerance:
        return False
    a = density[0][0].real
    b = density[1][1].real
    determinant = (density[0][0] * density[1][1] - density[0][1] * density[1][0]).real
    return a >= -tolerance and b >= -tolerance and determinant >= -tolerance


def _matrix_json(density: Matrix) -> List[List[dict]]:
    return [
        [
            {"re": round(density[row][col].real, 12), "im": round(density[row][col].imag, 12)}
            for col in range(2)
        ]
        for row in range(2)
    ]


def run_default_simulation(
    duration: float = 2.0,
    dt: float = 0.005,
    omega: float = 1.0,
    gamma_relaxation: float = 0.7,
    gamma_dephasing: float = 0.2,
) -> dict:
    if not math.isfinite(duration) or duration < 0.0:
        raise ValueError("duration must be finite and non-negative")
    if not math.isfinite(dt) or dt <= 0.0:
        raise ValueError("dt must be finite and positive")
    steps_float = duration / dt
    steps = round(steps_float)
    if not math.isclose(steps_float, steps, rel_tol=0.0, abs_tol=1e-9):
        raise ValueError("duration must be an integer multiple of dt")

    hamiltonian, jumps = make_operators(omega, gamma_relaxation, gamma_dephasing)
    trajectory = evolve(EXCITED_STATE, hamiltonian, jumps, dt=dt, steps=steps)
    _, final_state = trajectory[-1]
    x, y, z = bloch_vector(final_state)
    return {
        "experiment": "AVA_AVE_AVO_VIV_01610_15",
        "model": "single qubit under a Lindblad master equation",
        "units": "hbar = 1; rates and omega use inverse time units",
        "integrator": "fixed-step RK4 (approximate)",
        "parameters": {
            "duration": duration,
            "dt": dt,
            "steps": steps,
            "omega": omega,
            "gamma_relaxation": gamma_relaxation,
            "gamma_dephasing": gamma_dephasing,
        },
        "initial_density_matrix": _matrix_json(EXCITED_STATE),
        "final_density_matrix": _matrix_json(final_state),
        "final_bloch_vector": {"x": round(x, 12), "y": round(y, 12), "z": round(z, 12)},
        "diagnostics": {
            "trace_real": round(trace(final_state).real, 12),
            "trace_imag": round(trace(final_state).imag, 12),
            "hermiticity_error": round(hermiticity_error(final_state), 12),
            "purity": round(purity(final_state), 12),
            "is_density_matrix_within_1e-8": is_density_matrix(final_state, 1e-8),
        },
        "interpretation_note": (
            "Dephasing suppresses coherences; this model does not implement a projective "
            "measurement or prove a physical collapse of the wavefunction."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=float, default=2.0)
    parser.add_argument("--dt", type=float, default=0.005)
    parser.add_argument("--omega", type=float, default=1.0)
    parser.add_argument("--gamma-relaxation", type=float, default=0.7)
    parser.add_argument("--gamma-dephasing", type=float, default=0.2)
    args = parser.parse_args()
    result = run_default_simulation(
        duration=args.duration,
        dt=args.dt,
        omega=args.omega,
        gamma_relaxation=args.gamma_relaxation,
        gamma_dephasing=args.gamma_dephasing,
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
