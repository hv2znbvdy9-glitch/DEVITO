"""Bundled neuron-model analysis for AVA."""

from dataclasses import asdict, dataclass


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
