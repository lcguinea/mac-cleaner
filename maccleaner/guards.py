"""Protecciones del escáner.

Todo lo de este módulo se evalúa ANTES de descender a un directorio o de hacer lstat de un
fichero: las rutas protegidas se podan y no se inspeccionan. La configuración TOML solo
puede añadir protecciones; las de PROTECCION_FIJA no se pueden quitar.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

# Bases dentro de las que puede quedar una raíz de escaneo (tras realpath). Se expanden en
# tiempo de ejecución: "~" es el HOME real y "$TMPDIR" es el directorio temporal del usuario.
BASES_PERMITIDAS = (
    "~/Library/Caches",
    "~/Library/Logs",
    "~/.npm",
    "$TMPDIR",
    "/private/tmp",
)

# Protección mínima, no desactivable.
PROTECCION_FIJA_RUTAS = (
    "~/.claude", "~/.claude.json", "~/.codex", "~/.gemini", "~/.ssh", "~/.gnupg", "~/.aws",
    "~/.config", "~/.local", "~/.mac-cleaner", "~/.ollama", "~/.cache/huggingface",
    "~/Documents", "~/Desktop", "~/Downloads", "~/Pictures", "~/Music", "~/Movies",
    "~/Library/Keychains", "~/Library/Mail", "~/Library/Messages", "~/Library/Mobile Documents",
    "~/Library/Containers", "~/Library/Group Containers", "~/Library/Application Support",
    "~/Library/Preferences", "~/Library/Cookies", "~/Library/Safari", "~/Library/Photos",
    "/Volumes", "/System", "/Library", "/usr", "/bin", "/sbin", "/Applications",
)
PROTECCION_FIJA_NOMBRES = (
    r"(claude|anthropic)", r"argos", r"^rea($|[-_. ])", r"codex", r"(gemini|antigravity)", r"aeon",
    r"^\.?venv$", r"(keychain|\.ssh$|gnupg)",
    r"^\.mac-cleaner-(cuarentena|zona-sintetica)$",   # F2: la cuarentena nunca se escanea ni se planifica
)
PROTECCION_FIJA_MARCADORES = (".git", "pyvenv.cfg")


def expandir(ruta: str, home: str, tmpdir: str) -> str:
    """Expande ~ y $TMPDIR con valores explícitos (las pruebas usan un HOME ficticio)."""
    if ruta == "$TMPDIR" or ruta.startswith("$TMPDIR/"):
        ruta = tmpdir.rstrip("/") + ruta[len("$TMPDIR"):]
    elif ruta == "~" or ruta.startswith("~/"):
        ruta = home.rstrip("/") + ruta[1:]
    return os.path.normpath(ruta)


def bajo(ruta: str, base: str) -> bool:
    """True si ruta == base o cuelga de base (comparación por componentes, no por texto)."""
    return ruta == base or ruta.startswith(base.rstrip("/") + "/")


def real(ruta: str) -> str:
    """realpath sin fallar si la ruta no existe (para comparar prefijos de forma canónica)."""
    return os.path.realpath(ruta)


@dataclass
class Proteccion:
    home: str
    tmpdir: str
    rutas: list[str] = field(default_factory=list)
    nombres: list[str] = field(default_factory=list)
    extensiones: list[str] = field(default_factory=list)
    marcadores: list[str] = field(default_factory=list)
    bases: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        exp = lambda r: real(expandir(r, self.home, self.tmpdir))  # noqa: E731
        todas = list(PROTECCION_FIJA_RUTAS) + list(self.rutas)
        # Se guardan la forma expandida y la canónica, por si una de ellas es un enlace.
        self._rutas = sorted({exp(r) for r in todas} | {expandir(r, self.home, self.tmpdir) for r in todas})
        patrones = list(PROTECCION_FIJA_NOMBRES) + list(self.nombres)
        self._nombres = [re.compile(p, re.IGNORECASE) for p in patrones]
        # Una sola expresión para el caso común (no coincide); la lista se usa solo para el motivo.
        self._nombres_union = re.compile("|".join(f"(?:{p})" for p in patrones), re.IGNORECASE)
        self._ext = {e.lower() for e in self.extensiones}
        self._marcadores = set(PROTECCION_FIJA_MARCADORES) | set(self.marcadores)
        bases = self.bases or list(BASES_PERMITIDAS)
        self._bases = sorted({exp(b) for b in bases})

    # ── raíces ──
    def validar_raiz(self, ruta: str) -> tuple[str | None, str | None]:
        """Devuelve (raíz canónica, None) si se puede escanear o (None, motivo) si no."""
        canon = real(ruta)
        if not os.path.lexists(ruta):
            return None, "no existe"
        if not any(bajo(canon, b) for b in self._bases):
            return None, f"fuera de las bases permitidas ({canon})"
        motivo = self.motivo_ruta(canon)
        if motivo:
            return None, motivo
        # Una raíz de las bases puede estar DENTRO de una ruta protegida genérica (p. ej.
        # ~/Library/Caches no está protegida, pero /Library sí: se comparan rutas absolutas
        # del sistema, no del HOME, así que no hay colisión).
        return canon, None

    # ── rutas y nombres ──
    def motivo_ruta(self, ruta: str) -> str | None:
        for p in self._rutas:
            if bajo(ruta, p):
                # Las bases permitidas nunca se consideran protegidas por un prefijo del sistema
                # (/Library protege /Library/..., no ~/Library/Caches: rutas distintas).
                return f"ruta protegida: {p}"
        for comp in self._componentes_relativos(ruta):
            m = self.motivo_nombre(comp, es_dir=True)
            if m:
                return m
        return None

    def _componentes_relativos(self, ruta: str):
        for b in self._bases:
            if bajo(ruta, b):
                rel = ruta[len(b):].strip("/")
                return [c for c in rel.split("/") if c]
        return []

    def rutas_protegidas_bajo(self, raiz: str) -> frozenset[str]:
        """Prefijos protegidos que cuelgan de una raíz: el recorrido los poda por igualdad exacta."""
        return frozenset(p for p in self._rutas if bajo(p, raiz) and p != raiz)

    def motivo_nombre(self, nombre: str, es_dir: bool) -> str | None:
        if self._nombres_union.search(nombre):
            for rx in self._nombres:
                if rx.search(nombre):
                    return f"nombre protegido /{rx.pattern}/"
        if not es_dir:
            ext = os.path.splitext(nombre)[1].lower()
            if ext and ext in self._ext:
                return f"extensión protegida {ext}"
        return None

    def motivo_marcador(self, nombres_hijos) -> str | None:
        """Si el listado de un directorio contiene un marcador de proyecto o entorno, se poda."""
        hit = self._marcadores.intersection(nombres_hijos)
        if hit:
            return "proyecto/entorno (contiene " + ", ".join(sorted(hit)) + ")"
        return None
