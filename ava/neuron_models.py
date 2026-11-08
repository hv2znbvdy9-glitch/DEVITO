"""Bundled neuron-model analysis and safe reference helpers for AVA."""

from dataclasses import asdict, dataclass
from typing import Iterable


@dataclass(frozen=True)
class NeuronModelAnalysis:
    """Structured analysis of biologically plausible neuron models."""

    title: str
    candidate: str
    comparison_to_lif: str
    single_neuron_highlights: list[str]
    network_scale_example: list[str]
    missing_for_reference_grade_model: list[str]
    bottom_line: str
    sources: list[str]

    def to_dict(self) -> dict:
        """Convert the analysis to a JSON-serializable dictionary."""
        return asdict(self)


@dataclass(frozen=True)
class HayL5bReferenceSpec:
    """Reference metadata for the Hay et al. L5b pyramidal-cell model.

    This object deliberately does not claim to reproduce the published NEURON
    model. A reference-grade run requires the published morphology,
    mechanism/kinetics files, parameter distributions and simulator setup.
    """

    name: str
    model_class: str
    compartments: tuple[str, ...]
    active_mechanism_families: tuple[str, ...]
    supported_phenomena: tuple[str, ...]
    required_runtime_assets: tuple[str, ...]
    simulation_ready: bool
    limitation: str
    source: str

    def to_dict(self) -> dict:
        """Convert the reference specification to a serializable dictionary."""
        return asdict(self)


def get_hay_l5b_reference_spec() -> HayL5bReferenceSpec:
    """Return a conservative executable specification for Hay-style modelling."""
    return HayL5bReferenceSpec(
        name="Hay et al. L5b pyramidal-cell model",
        model_class=(
            "active multi-compartment conductance-based model of a "
            "morphologically reconstructed layer-5b pyramidal neuron"
        ),
        compartments=(
            "soma",
            "apical dendrites",
            "basal dendrites",
            "axon/initial segment approximation",
        ),
        active_mechanism_families=(
            "voltage-gated sodium currents",
            "voltage-gated potassium currents",
            "calcium currents",
            "calcium-dependent currents",
            "HCN current",
            "passive leak",
        ),
        supported_phenomena=(
            "somatic action potentials",
            "back-propagating action potentials",
            "dendritic calcium spikes",
            "burst firing",
            "spatially distributed dendritic integration",
        ),
        required_runtime_assets=(
            "NEURON-compatible simulator",
            "published morphology reconstruction",
            "published mechanism/kinetics files",
            "published regional parameter distributions",
            "stimulus and recording protocol",
        ),
        simulation_ready=False,
        limitation=(
            "AVA contains a reference/scaffold only. It does not embed the "
            "published morphology or mechanism files and therefore must not be "
            "reported as a full Hay-model simulation."
        ),
        source=(
            "Hay et al. (2011), Models of Neocortical Layer 5b Pyramidal "
            "Cells Capturing a Wide Range of Dendritic and Perisomatic Active "
            "Properties, PLOS Computational Biology."
        ),
    )


def conductance_current(
    conductance: float,
    voltage: float,
    reversal_potential: float,
) -> float:
    """Return an outward-positive conductance current: g * (V - E)."""
    if conductance < 0:
        raise ValueError("conductance must be non-negative")
    return conductance * (voltage - reversal_potential)


def axial_current(
    coupling_conductance: float,
    neighbor_voltage: float,
    local_voltage: float,
) -> float:
    """Return current flowing into a compartment from an electrically coupled neighbor."""
    if coupling_conductance < 0:
        raise ValueError("coupling_conductance must be non-negative")
    return coupling_conductance * (neighbor_voltage - local_voltage)


def compartment_voltage_derivative(
    capacitance: float,
    applied_current: float,
    ionic_currents: Iterable[float],
    axial_currents: Iterable[float],
) -> float:
    """Evaluate a generic multi-compartment cable-equation voltage derivative.

    Sign convention:
    - applied_current and axial_currents are positive into the compartment;
    - ionic_currents are outward-positive.

    All values must use one internally consistent unit system.
    """
    if capacitance <= 0:
        raise ValueError("capacitance must be positive")

    return (
        applied_current
        + sum(axial_currents)
        - sum(ionic_currents)
    ) / capacitance


def euler_voltage_step(
    voltage: float,
    dt: float,
    dv_dt: float,
) -> float:
    """Advance one voltage state with an explicit Euler step."""
    if dt <= 0:
        raise ValueError("dt must be positive")
    return voltage + dt * dv_dt


def get_neuron_model_analysis() -> NeuronModelAnalysis:
    """Return the bundled analysis for complex neuron models."""
    return NeuronModelAnalysis(
        title="Biologisch plausible Neuronenmodelle",
        candidate=(
            "Ein aktives Multi-Kompartiment-Hodgkin-Huxley-Modell einer "
            "morphologisch rekonstruierten Schicht-5-Pyramidenzelle zählt zu "
            "den stärksten Kandidaten für ein besonders komplexes "
            "Einzelneuronenmodell."
        ),
        comparison_to_lif=(
            "Gegenüber einem Leaky-Integrate-and-Fire-Neuron ist dies eine "
            "grundlegend andere Detailklasse mit räumlich verteilten "
            "Dendriten, aktiven Ionenkanälen, lokalen Nichtlinearitäten und "
            "rücklaufenden Aktionspotenzialen."
        ),
        single_neuron_highlights=[
            (
                "Hay et al. modelliert eine aktive L5b-Pyramidenzelle mit "
                "rekonstruierter Morphologie und dendritischen Calciumspikes."
            ),
            (
                "DeepDendrite demonstriert ein menschliches "
                "Pyramidenzellmodell mit 24.994 explizit modellierten "
                "dendritischen Spines."
            ),
            (
                "Solche Modelle können Burst-Feuern, dendritische "
                "Nichtlinearitäten und die Integration räumlich getrennter "
                "Eingänge erfassen."
            ),
        ],
        network_scale_example=[
            "31.346 biophysikalische Hodgkin-Huxley-Neuronen",
            "7,8 Millionen neuronale Verbindungen",
            "36,4 Millionen Synapsen",
            "55 morphologische Zelltypen",
            "stochastische Vesikelfreisetzung und teilweise stochastische Ionenkanäle",
        ],
        missing_for_reference_grade_model=[
            "vollständige 3D-Morphologie mit sämtlichen relevanten Ionenkanälen",
            "explizite Synapsen und vollständig aktive Spines",
            "Calcium- und weitere Botenstoffsysteme",
            "kurz- und langfristige Plastizität",
            "Neuromodulatoren, Genexpression und Proteinsynthese",
            "Zellstoffwechsel, Wachstum und Glia-Interaktion",
            "umfassende experimentelle Validierung und Unsicherheitsabschätzung",
        ],
        bottom_line=(
            "Ein vollständig integriertes, experimentell umfassend validiertes "
            "digitales Neuron dieser maximalen Detailtiefe existiert derzeit "
            "nicht; komplexere Modelle sind nicht automatisch realistischer."
        ),
        sources=[
            "Hay et al. (PLOS Computational Biology, 2011)",
            "DeepDendrite (Nature Communications, 2023)",
            "Cortical reliability amid noise and chaos (Nature Communications, 2019)",
            "Toward Reference-Grade neuron models (Communications Biology, 2026)",
        ],
    )
