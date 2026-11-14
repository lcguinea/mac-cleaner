"""Manifiesto persistente de una operación: JSON Lines con encadenamiento SHA-256 y fsync por registro.

Cada registro lleva `prev` (huella del anterior) y `h` = SHA-256(prev + JSON canónico del registro sin `h`).
Editar, borrar o reordenar un registro rompe la cadena y se detecta al cargar. Truncar el FINAL no se
puede detectar con la cadena sola; por eso existe el registro `cierre`, y `purge` nunca toca
operaciones sin cierre. Es una huella de integridad, NO una firma autenticada: quien pueda escribir el
fichero puede recalcular la cadena entera.

Protocolo de escritura anticipada: antes de mover se escribe `intento`, después `movido`. Si el proceso
muere entre ambos, `restore` localiza el fichero por su inodo (en el origen o en la cuarentena).

Concurrencia (F2.5): apply, restore y purge toman un bloqueo exclusivo (flock) del manifiesto durante toda
la operación y recargan su contenido después de obtenerlo. Además, `anotar` comprueba que el fichero tiene
exactamente el tamaño que este objeto escribió o leyó: si otro proceso añadió registros, se niega a escribir
en lugar de romper la cadena. El manifiesto nunca se abre siguiendo enlaces simbólicos.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import stat
import time

CERO = "0" * 64


class ManifiestoCorrupto(ValueError):
    pass


class ManifiestoOcupado(RuntimeError):
    """Otro proceso tiene bloqueada la operación (apply, restore o purge en curso)."""


def _abrir_lectura(ruta: str) -> int:
    fd = os.open(ruta, os.O_RDONLY | os.O_NOFOLLOW)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise OSError(f"el manifiesto no es un fichero regular: {ruta}")
    return fd


def _canon(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _huella(prev: str, reg: dict) -> str:
    return hashlib.sha256(prev.encode() + _canon(reg)).hexdigest()


class Manifiesto:
    def __init__(self, ruta: str, registros: list[dict] | None = None, tam: int = 0):
        self.ruta = ruta
        self.registros = registros or []
        self._tam = tam            # bytes del fichero que este objeto conoce (leídos o escritos)

    @property
    def ultimo(self) -> str:
        return self.registros[-1]["h"] if self.registros else CERO

    def anotar(self, evento: str, **datos) -> dict:
        reg = {"n": len(self.registros), "t": time.time(), "evento": evento, "prev": self.ultimo, **datos}
        reg["h"] = _huella(reg["prev"], {k: v for k, v in reg.items() if k != "h"})
        linea = (json.dumps(reg, ensure_ascii=False, sort_keys=True) + "\n").encode()
        # Ruta absoluta (la guardia la comprueba) y O_NOFOLLOW: un enlace en lugar del manifiesto da ELOOP.
        fd = os.open(self.ruta, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise OSError(f"el manifiesto no es un fichero regular: {self.ruta}")
            if st.st_size != self._tam:
                raise ManifiestoCorrupto("el manifiesto cambió desde que se cargó (¿otro proceso?): "
                                         "no se escribe para no romper la cadena")
            escrito = 0
            while escrito < len(linea):
                escrito += os.write(fd, linea[escrito:])
            os.fsync(fd)
        finally:
            os.close(fd)
        self._tam += len(linea)
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
            fd = _abrir_lectura(ruta)
            with os.fdopen(fd, "rb") as fh:
                datos = fh.read()
            lineas = datos.decode("utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
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
        if not datos.endswith(b"\n"):
            raise ManifiestoCorrupto("el manifiesto termina en una línea incompleta")
        return cls(ruta, regs, tam=len(datos))

    @contextlib.contextmanager
    def bloquear(self):
        """Bloqueo exclusivo de la operación (no espera: si está ocupada, ManifiestoOcupado). Al obtenerlo
        se recarga el contenido, de modo que las decisiones se toman sobre el estado más reciente."""
        try:
            fd = _abrir_lectura(self.ruta)
        except OSError as exc:
            raise ManifiestoCorrupto(f"no se puede abrir el manifiesto: {exc}") from exc
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ManifiestoOcupado("la operación está ocupada por otro proceso (apply, restore o purge)") from exc
            if os.fstat(fd).st_size != self._tam:
                fresco = Manifiesto.cargar(self.ruta)
                self.registros, self._tam = fresco.registros, fresco._tam
            yield self
        finally:
            os.close(fd)                 # cerrar el descriptor libera el flock

    # ── consultas ──
    @property
    def inicio(self) -> dict:
        return self.registros[0]

    @property
    def cerrado(self) -> bool:
        return any(r["evento"] == "cierre" for r in self.registros)

    def estados(self) -> dict[str, dict]:
        """Estado actual por elemento: intento | movido | omitido | error | restaurado | purgado | no_movido | retenido."""
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
                if r["evento"] == "movido":
                    e["ctime_movido"] = r.get("ctime_ns")   # para detectar cambios en cuarentena sin SHA-256
            elif r["evento"] == "conflicto":
                e["ultimo_conflicto"] = r.get("motivo")   # el fichero sigue en cuarentena (estado movido)
            elif r["evento"] == "restaurar_error":
                e["ultimo_error"] = r.get("motivo")       # sigue en cuarentena: restore se puede reintentar
            elif r["evento"] == "sustitucion_revertida":
                e["estado"] = "omitido"
                e["motivo"] = "sustitución detectada y revertida"
            elif r["evento"] == "sustitucion_no_revertida":
                # Un objeto AJENO quedó en la cuarentena y no se pudo devolver: nunca se restaura ni se purga
                # automáticamente; requiere revisión manual.
                e.update(estado="retenido", retenido_en=r.get("destino"), motivo=r.get("motivo"))
        return est
