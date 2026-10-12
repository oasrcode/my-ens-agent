"""ENS catalog: data model, OSCAL loader and applicability engine."""

from .applicability import (
    ApplicabilityResult,
    MedidaAplicable,
    compute_applicability,
    derive_categoria,
)
from .loader import build_catalog, load_catalog
from .models import (
    AplicacionPor,
    Catalog,
    Categoria,
    Dimension,
    Medida,
    Nivel,
    Refuerzo,
    Requisito,
    SeleccionRefuerzo,
)

__all__ = [
    "AplicacionPor",
    "ApplicabilityResult",
    "Catalog",
    "Categoria",
    "Dimension",
    "Medida",
    "MedidaAplicable",
    "Nivel",
    "Refuerzo",
    "Requisito",
    "SeleccionRefuerzo",
    "build_catalog",
    "compute_applicability",
    "derive_categoria",
    "load_catalog",
]
