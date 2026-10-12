# AVA / AVE / AVO / VIV 01610–15 — reproducible open-qubit experiment

This experiment implements a dependency-free numerical model of one qubit under the Lindblad master equation. It is kept separate from AVA's defensive Windows/security code and does not alter the operating system or perform network activity.

## Model

With \(\hbar=1\), the evolution is

\[
\frac{d\rho}{dt}=-i[H,\rho]+\sum_j\left(L_j\rho L_j^\dagger-\frac12\{L_j^\dagger L_j,\rho\}\right).
\]

The default Hamiltonian is \(H=(\omega/2)\sigma_z\). Jump operators model amplitude damping \(\sqrt{\gamma_1}|0\rangle\langle1|\) and pure dephasing \(\sqrt{\gamma_\phi/2}\,\sigma_z\). A fixed-step fourth-order Runge–Kutta integrator is used, so results are approximations; reduce the step size to assess convergence for more demanding work.

The program reports the final density matrix, Bloch vector, trace, Hermiticity error, purity, and a simple 2×2 density-matrix validity check. It distinguishes suppression of coherence (dephasing) from projective measurement; it does not claim to simulate consciousness or establish a physical wavefunction collapse.

## Run locally

    python experiments/ava_ave_avo_viv_01610_15.py
    python -m unittest discover -s tests -p 'test_ava_ave_avo_viv_01610_15.py' -v

Custom parameters are available via command-line options: duration, dt, omega, gamma-relaxation, and gamma-dephasing.

## Acceptance checks

The focused tests cover trace preservation, Hermiticity, positivity for the tested trajectory, analytic amplitude-damping population, pure-dephasing coherence decay, the Bloch-vector convention, and input validation. GitHub Actions runs this focused test module on Python 3.10 and 3.12; the broader pre-existing repository suite is not treated as evidence for this isolated experiment.
