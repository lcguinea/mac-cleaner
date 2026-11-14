"""Manifiesto persistente de una operación: JSON Lines con encadenamiento SHA-256 y fsync por registro.

Cada registro lleva `prev` (huella del anterior) y `h` = SHA-256(prev + JSON canónico del registro sin `h`).
Editar, borrar o reordenar un registro rompe la cadena y se detecta al cargar. Truncar el FINAL no se
puede detectar con la cadena sola; por eso existe el registro `cierre`, y `purge` nunca toca
operaciones sin cierre. Es una huella de integridad, NO una firma autenticada: quien pueda escribir el
fichero puede recalcular la cadena entera.

Protocolo de escritura anticipada: antes de mover se escribe `intento`, después `movido`. Si el proceso
muere entre ambos, `restore` localiza el fichero por su inodo (en el origen o en la cuarentena).
"""
from __future__ import annotations

import hashlib
import json
import os
import time

CERO = "0" * 64


class ManifiestoCorrupto(ValueError):
    pass


def _canon(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _huella(prev: str, reg: dict) -> str:
    return hashlib.sha256(prev.encode() + _canon(reg)).hexdigest()


class Manifiesto:
    def __init__(self, ruta: str, registros: list[dict] | None = None):
        self.ruta = ruta
        self.registros = registros or []

    @property
    def ultimo(self) -> str:
        return self.registros[-1]["h"] if self.registros else CERO

    def anotar(self, evento: str, **datos) -> dict:
        reg = {"n": len(self.registros), "t": time.time(), "evento": evento, "prev": self.ultimo, **datos}
        reg["h"] = _huella(reg["prev"], {k: v for k, v in reg.items() if k != "h"})
        linea = json.dumps(reg, ensure_ascii=False, sort_keys=True) + "\n"
        with open(self.ruta, "a", encoding="utf-8") as fh:
            fh.write(linea)
            fh.flush()
            os.fsync(fh.fileno())
        self.registros.append(reg)
        return reg

    @classmethod
    def crear(cls, ruta: str, **inicio) -> "Manifiesto":
        fd = os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        m = cls(ruta)
        m.anotar("inicio", **inicio)
        return m

    @classmethod
    def cargar(cls, ruta: str) -> "Manifiesto":
        regs, prev = [], CERO
        try:
            with open(ruta, encoding="utf-8") as fh:
                lineas = fh.read().splitlines()
        except OSError as exc:
            raise ManifiestoCorrupto(f"no se puede leer el manifiesto: {exc}") from exc
        for i, linea in enumerate(lineas):
            try:
                reg = json.loads(linea)
            except json.JSONDecodeError as exc:
                raise ManifiestoCorrupto(f"línea {i + 1} no es JSON válido") from exc
            if reg.get("n") != i or reg.get("prev") != prev:
                raise ManifiestoCorrupto(f"cadena rota en la línea {i + 1} (orden o registro anterior alterado)")
            if _huella(prev, {k: v for k, v in reg.items() if k != "h"}) != reg.get("h"):
                raise ManifiestoCorrupto(f"huella no válida en la línea {i + 1} (registro modificado)")
            regs.append(reg)
            prev = reg["h"]
        if not regs or regs[0]["evento"] != "inicio":
            raise ManifiestoCorrupto("el manifiesto no empieza por un registro de inicio")
        return cls(ruta, regs)

    # ── consultas ──
    @property
    def inicio(self) -> dict:
        return self.registros[0]

    @property
    def cerrado(self) -> bool:
        return any(r["evento"] == "cierre" for r in self.registros)

    def estados(self) -> dict[str, dict]:
        """Estado actual por elemento: planificado | intento | movido | omitido | error | restaurado | conflicto | purgado."""
        est: dict[str, dict] = {}
        for r in self.registros:
            eid = r.get("id")
            if not eid:
                continue
            e = est.setdefault(eid, {"id": eid})
            if r["evento"] == "intento":
                e.update(estado="intento", origen=r["origen"], destino=r["destino"], meta=r["meta"])
            elif r["evento"] in ("movido", "omitido", "error", "restaurado", "purgado", "no_movido"):
                e["estado"] = r["evento"]
                if r["evento"] in ("omitido", "error"):
                    e["motivo"] = r.get("motivo")
            elif r["evento"] == "conflicto":
                e["ultimo_conflicto"] = r.get("motivo")   # el fichero sigue en cuarentena (estado movido)
            elif r["evento"] == "sustitucion_revertida":
                e["estado"] = "omitido"
                e["motivo"] = "sustitución detectada y revertida"
        return est
