"""OSCAL loader: parse the official AEAD ENS catalog into Pydantic models.

The source document (``data/ens_anexo_ii_oscal.json``) has the shape::

    catalog
      uuid, metadata (version, oscal-version, last-modified, props, links)
      groups: [ marco groups ]
        - "org": family group with controls directly
        - "op"/"mp": family groups nesting one subfamily group per familia
      each control: id, title, props, parts[name=requisitos], controls[]
        - nested control class == "ens-refuerzo" -> Refuerzo

``marco`` is derived from the top-level group id and ``familia`` from the
subgroup id (falling back to the marco id for the organizational group).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

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

_REFUERZO_CLASS = "ens-refuerzo"
_REFUERZO_ORDER_RE = re.compile(r"\.r(\d+)$")
_SELECCION_TIPO = "seleccion-refuerzo"


def _props(node: dict[str, Any], name: str) -> list[Any]:
    """Return all property values with the given name."""
    return [p.get("value") for p in node.get("props", []) if p.get("name") == name]


def _prop(node: dict[str, Any], name: str) -> Any | None:
    """Return the first property value with the given name, if any."""
    values = _props(node, name)
    return values[0] if values else None


def _enum_list(enum_cls: type, values: Iterable[Any]) -> list[Any]:
    """Coerce raw values into enum members, skipping unknown ones."""
    out: list[Any] = []
    for value in values:
        try:
            out.append(enum_cls(value))
        except ValueError:
            continue
    return out


def _collect_items(part: dict[str, Any], out: list[Requisito]) -> None:
    """Recursively flatten ``item`` parts (which may nest further items)."""
    if part.get("name") != "item":
        return
    prose = part.get("prose")
    if prose:
        out.append(
            Requisito(
                id=part.get("id", ""),
                label=_prop(part, "label"),
                texto=prose,
            )
        )
    for child in part.get("parts", []):
        _collect_items(child, out)


def _extract_requisitos(control: dict[str, Any]) -> list[Requisito]:
    """Collect the literal requirement items of a control's ``requisitos`` part."""
    out: list[Requisito] = []
    for part in control.get("parts", []):
        if part.get("name") != "requisitos":
            continue
        for item in part.get("parts", []):
            _collect_items(item, out)
    return out


def _parse_seleccion(control: dict[str, Any]) -> list[SeleccionRefuerzo]:
    """Extract mutually-exclusive refuerzo selection groups from ``params``."""
    groups: list[SeleccionRefuerzo] = []
    for param in control.get("params", []):
        if _prop(param, "tipo-param") != _SELECCION_TIPO:
            continue
        categoria = _prop(param, "categoria")
        nivel = _prop(param, "nivel")
        choices = param.get("select", {}).get("choice", [])
        groups.append(
            SeleccionRefuerzo(
                categoria=Categoria(categoria) if categoria else None,
                nivel=Nivel(nivel) if nivel else None,
                opciones=list(choices),
            )
        )
    return groups


def _parse_refuerzo(control: dict[str, Any]) -> Refuerzo:
    """Parse a nested control of class ``ens-refuerzo``."""
    ref_id = control["id"]
    match = _REFUERZO_ORDER_RE.search(ref_id)
    order = int(match.group(1)) if match else 0
    categorias = _enum_list(Categoria, _props(control, "categoria"))
    niveles = _enum_list(Nivel, _props(control, "nivel"))
    aplicacion_por = _prop(control, "aplicacion-por")
    return Refuerzo(
        id=ref_id,
        order=order,
        nombre=control.get("title", ""),
        opcional=aplicacion_por is None and not categorias and not niveles,
        categorias=categorias,
        niveles=niveles,
        dimensiones=_enum_list(Dimension, _props(control, "dimension")),
        requisitos=_extract_requisitos(control),
    )


def _parse_medida(
    control: dict[str, Any],
    *,
    marco: str,
    familia: str,
    familia_nombre: str,
) -> Medida:
    """Parse a base control into a :class:`Medida`."""
    seleccion = _parse_seleccion(control)
    refuerzos = [
        _parse_refuerzo(nested)
        for nested in control.get("controls", [])
        if nested.get("class") == _REFUERZO_CLASS
    ]
    # Derive each refuerzo's mutually-exclusive alternatives from selection groups.
    for refuerzo in refuerzos:
        alternativas: set[str] = set()
        for group in seleccion:
            if refuerzo.id in group.opciones:
                alternativas.update(o for o in group.opciones if o != refuerzo.id)
        refuerzo.alternativas = sorted(alternativas)

    aplicacion_por = _prop(control, "aplicacion-por")
    return Medida(
        code=control["id"],
        name=control.get("title", ""),
        marco=marco,
        familia=familia,
        familia_nombre=familia_nombre,
        dimensiones=_enum_list(Dimension, _props(control, "dimension")),
        aplicacion_por=(
            AplicacionPor(aplicacion_por)
            if aplicacion_por
            else AplicacionPor.CATEGORIA
        ),
        categorias=_enum_list(Categoria, _props(control, "categoria")),
        niveles=_enum_list(Nivel, _props(control, "nivel")),
        requisitos=_extract_requisitos(control),
        refuerzos=refuerzos,
        seleccion=seleccion,
    )


def _parse_metadata(catalog: dict[str, Any]) -> dict[str, str]:
    """Extract catalog-level provenance metadata."""
    metadata = catalog.get("metadata", {})
    links = metadata.get("links", [])
    fuente = next(
        (link.get("href", "") for link in links if link.get("rel") == "source"),
        "",
    )
    licencia = _prop(metadata, "license")
    if not licencia:
        licencia = next(
            (link.get("href", "") for link in links if link.get("rel") == "license"),
            "",
        )
    return {
        "norma": _prop(metadata, "source") or fuente,
        "titulo": metadata.get("title", ""),
        "uuid": catalog.get("uuid", ""),
        "version": metadata.get("version", ""),
        "oscal_version": metadata.get("oscal-version", ""),
        "last_modified": metadata.get("last-modified", ""),
        "fuente": fuente,
        "licencia": licencia,
    }


def build_catalog(document: dict[str, Any]) -> Catalog:
    """Build a :class:`Catalog` from a parsed OSCAL document."""
    catalog = document.get("catalog", document)
    medidas: dict[str, Medida] = {}

    for group in catalog.get("groups", []):
        marco = group.get("id", "")
        familia_nombre = group.get("title", "")
        # Families with a single level (organizational marco) keep controls here.
        for control in group.get("controls", []):
            medida = _parse_medida(
                control,
                marco=marco,
                familia=marco,
                familia_nombre=familia_nombre,
            )
            medidas[medida.code] = medida
        # Frameworks that nest per-family subgroups (operational/protection).
        for subgroup in group.get("groups", []):
            subfamilia = subgroup.get("id", "")
            subnombre = subgroup.get("title", "")
            for control in subgroup.get("controls", []):
                medida = _parse_medida(
                    control,
                    marco=marco,
                    familia=subfamilia,
                    familia_nombre=subnombre,
                )
                medidas[medida.code] = medida

    return Catalog(medidas=medidas, **_parse_metadata(catalog))


def load_catalog(path: str | Path) -> Catalog:
    """Load and parse the OSCAL ENS catalog from a JSON file path."""
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    return build_catalog(document)
