"""Integración de Homebrew, npm y pip: qué es reversible y qué no. F2 NO EJECUTA ninguna orden de limpieza.

Conclusión (14-11-2026): las órdenes oficiales de limpieza borran directamente (no usan la Papelera ni
ofrecen deshacer). Para mantener la reversibilidad, mac-cleaner trata sus cachés como ficheros normales:
`plan` + `apply` las MUEVEN a cuarentena. Las herramientas no guardan estado sobre su caché fuera de ella,
así que tras moverla la regeneran al necesitarla, y `restore` la devuelve intacta si hiciera falta.
Las órdenes oficiales quedan documentadas como alternativa IRREVERSIBLE que exigiría autorización aparte.
"""
from __future__ import annotations

OPERACIONES = [
    # ── reversibles (consulta o simulación; mac-cleaner las usa o puede usarlas) ──
    {"herramienta": "brew", "orden": "brew --cache", "efecto": "imprime la ruta de la caché", "reversible": True,
     "destructiva": False, "uso": "F1: localizar la caché"},
    {"herramienta": "brew", "orden": "brew cleanup -n --prune=30", "efecto": "lista lo que borraría (dry-run)",
     "reversible": True, "destructiva": False,
     "uso": "opcional (--brew-dry-run). El 14-11 cambió una vez el listado de metadatos de la caché (causa no "
            "determinada); por eso no se ejecuta por defecto. Su salida incluye rutas FUERA de la caché "
            "(Cellar, portable-ruby) que mac-cleaner nunca mueve"},
    {"herramienta": "pip", "orden": "pip cache dir | info --disable-pip-version-check", "efecto": "consulta",
     "reversible": True, "destructiva": False, "uso": "F1: localizar y dimensionar la caché"},
    {"herramienta": "npm", "orden": "(no se ejecuta) $npm_config_cache / ~/.npmrc", "efecto": "lee la configuración",
     "reversible": True, "destructiva": False, "uso": "F1: npm escribe logs en _logs en cada orden, por eso no se lanza"},
    {"herramienta": "*", "orden": "mac-cleaner plan + apply (cuarentena)", "efecto": "mueve la caché a cuarentena (rename)",
     "reversible": True, "destructiva": False,
     "uso": "F2 (zona sintética) → F3 con autorización: vía recomendada para las tres herramientas"},
    # ── irreversibles (borran directamente; NO se ejecutan) ──
    {"herramienta": "brew", "orden": "brew cleanup [--prune=N] [-s]",
     "efecto": "borra descargas antiguas de la caché Y versiones antiguas de fórmulas en el Cellar",
     "reversible": False, "destructiva": True, "uso": "no ejecutar: afecta fuera de la caché"},
    {"herramienta": "brew", "orden": "brew autoremove", "efecto": "desinstala dependencias huérfanas",
     "reversible": False, "destructiva": True, "uso": "fuera del alcance (no es limpieza de caché)"},
    {"herramienta": "npm", "orden": "npm cache clean --force", "efecto": "borra _cacache entero",
     "reversible": False, "destructiva": True, "uso": "equivalente reversible: mover ~/.npm/_cacache a cuarentena"},
    {"herramienta": "npm", "orden": "npm cache verify", "efecto": "verifica Y recolecta basura (borra contenido no referenciado)",
     "reversible": False, "destructiva": True, "uso": "no ejecutar: parece una consulta, pero borra"},
    {"herramienta": "pip", "orden": "pip cache purge | pip cache remove <patrón>", "efecto": "borra http-v2/http/wheels",
     "reversible": False, "destructiva": True, "uso": "equivalente reversible: mover la caché de pip a cuarentena"},
]


def reversibles() -> list[dict]:
    return [o for o in OPERACIONES if o["reversible"]]


def destructivas() -> list[dict]:
    return [o for o in OPERACIONES if o["destructiva"]]
