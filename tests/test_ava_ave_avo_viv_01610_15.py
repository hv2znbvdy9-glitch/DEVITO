"""Regression tests for AVA/AVE/AVO/VIV 01610-15 Lindblad simulation."""
from __future__ import annotations

import math
import unittest

from experiments.ava_ave_avo_viv_01610_15 import (
    EXCITED_STATE,
    PLUS_STATE,
    SIGMA_Z,
    bloch_vector,
    evolve,
    is_density_matrix,
    make_operators,
    purity,
    trace,
)


class LindbladQubitTests(unittest.TestCase):
    def test_zero_rate_excited_state_is_stationary_for_z_hamiltonian(self) -> None:
        hamiltonian, jumps = make_operators(omega=1.3, gamma_relaxation=0.0, gamma_dephasing=0.0)
        trajectory = evolve(EXCITED_STATE, hamiltonian, jumps, dt=0.01, steps=100)
        for _, state in trajectory:
            self.assertTrue(is_density_matrix(state, tolerance=1e-9))
            self.assertAlmostEqual(state[1][1].real, 1.0, places=9)
            self.assertAlmostEqual(abs(state[0][1]), 0.0, places=9)

    def test_amplitude_damping_matches_analytic_population(self) -> None:
        gamma = 0.8
        duration = 1.0
        dt = 0.001
        hamiltonian, jumps = make_operators(
            omega=0.0, gamma_relaxation=gamma, gamma_dephasing=0.0
        )
        final_state = evolve(
            EXCITED_STATE, hamiltonian, jumps, dt=dt, steps=round(duration / dt)
        )[-1][1]
        self.assertAlmostEqual(final_state[1][1].real, math.exp(-gamma * duration), places=9)
        self.assertAlmostEqual(
            final_state[0][0].real, 1.0 - math.exp(-gamma * duration), places=9
        )

    def test_pure_dephasing_preserves_populations_and_damps_coherence(self) -> None:
        gamma = 0.6
        duration = 1.0
        dt = 0.001
        hamiltonian, jumps = make_operators(
            omega=0.0, gamma_relaxation=0.0, gamma_dephasing=gamma
        )
        final_state = evolve(
            PLUS_STATE, hamiltonian, jumps, dt=dt, steps=round(duration / dt)
        )[-1][1]
        expected_coherence = 0.5 * math.exp(-gamma * duration)
        self.assertAlmostEqual(final_state[0][0].real, 0.5, places=10)
        self.assertAlmostEqual(final_state[1][1].real, 0.5, places=10)
        self.assertAlmostEqual(final_state[0][1].real, expected_coherence, places=9)
        self.assertAlmostEqual(final_state[0][1].imag, 0.0, places=10)
        self.assertTrue(is_density_matrix(final_state, tolerance=1e-9))

    def test_trace_hermiticity_and_positivity_across_mixed_evolution(self) -> None:
        hamiltonian, jumps = make_operators(
            omega=1.0, gamma_relaxation=0.7, gamma_dephasing=0.2
        )
        trajectory = evolve(EXCITED_STATE, hamiltonian, jumps, dt=0.002, steps=1000)
        for _, state in trajectory:
            self.assertAlmostEqual(trace(state).real, 1.0, places=9)
            self.assertAlmostEqual(trace(state).imag, 0.0, places=9)
            self.assertTrue(is_density_matrix(state, tolerance=2e-9))
        self.assertLess(purity(trajectory[-1][1]), 1.0)

    def test_bloch_vector_for_plus_state(self) -> None:
        x, y, z = bloch_vector(PLUS_STATE)
        self.assertAlmostEqual(x, 1.0, places=12)
        self.assertAlmostEqual(y, 0.0, places=12)
        self.assertAlmostEqual(z, 0.0, places=12)

    def test_invalid_rates_and_time_step_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            make_operators(omega=1.0, gamma_relaxation=-0.1, gamma_dephasing=0.0)
        with self.assertRaises(ValueError):
            evolve(EXCITED_STATE, SIGMA_Z, dt=0.0, steps=1)
        with self.assertRaises(ValueError):
            evolve(EXCITED_STATE, SIGMA_Z, dt=0.01, steps=-1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
