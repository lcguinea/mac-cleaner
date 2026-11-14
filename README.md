# mac-cleaner

Alternativa propia a las funciones de limpieza de CleanMyMac, basada en la investigación REA-004
(informe y evidencias locales, no versionados: contienen metadatos de binarios propietarios y datos del equipo).

**Estado: F2.**
- F1 (`scan`, `report`) es de solo lectura y funciona sobre el Mac real.
- F2 (`plan`, `apply`, `restore`, `purge`) añade limpieza **reversible** mediante cuarentena. Hoy está restringida a
  **zonas sintéticas** (directorios temporales de prueba con marcador): la limpieza de datos reales está
  deshabilitada en el código (`zona.LIMPIEZA_REAL_HABILITADA = False`). Ver `docs/SEGURIDAD-F2.md`.

## Uso

```bash
./mac-cleaner scan --informe     # escanea y guarda informes/scan-AAAAMMDD-HHMMSS.{json,md}
./mac-cleaner report             # vuelve a generar el Markdown del escaneo más reciente (salida estándar)
./mac-cleaner report --entrada informes/scan-….json --out informe.md
./mac-cleaner scan --regla npm --regla pip     # solo algunas reglas
./mac-cleaner scan --sin-lsof                  # sin la instantánea de ficheros abiertos
./mac-cleaner scan --brew-dry-run              # añade `brew cleanup -n` (ver «Herramientas»)
```

### F2 (solo zonas sintéticas)

```bash
./mac-cleaner demo                                     # ciclo completo en una zona nueva con ficheros ficticios
./mac-cleaner scan --zona-sintetica ZONA --config ZONA/reglas.toml
./mac-cleaner plan --entrada ZONA/informes/scan-….json  # revalida AHORA; caduca en 24 h
./mac-cleaner apply --plan ZONA/informes/plan-….json    # mueve a ZONA/.mac-cleaner-cuarentena/<op>/
./mac-cleaner restore --zona ZONA --operacion OP [--elemento e000003 | --ruta RUTA]
./mac-cleaner purge --zona ZONA [--dias 14] [--ejecutar]   # sin --ejecutar solo lista
./mac-cleaner oficiales                                # brew, npm y pip: reversibles frente a destructivas
```

Una zona sintética es un directorio bajo `$TMPDIR` o `/private/tmp` con el marcador
`.mac-cleaner-zona-sintetica` (lo crea `zona.crear_zona()` o `demo`), con `home/` y `tmp/` ficticios dentro.
`plan` también acepta un escaneo real y produce una **vista previa**, pero `apply` la rechaza.

- **`plan`**: elige los grupos con «recuperable conservador» del escaneo (≤ 24 h) y los vuelve a recorrer en el momento, con las protecciones de F1 y lsof nuevo. Excluye lo protegido, lo activo, lo abierto, el riesgo alto y los enlaces duros. Guarda por fichero `st_dev`, `st_ino`, uid, modo, tamaño, `mtime_ns`, `ctime_ns`, birthtime y SHA-256, junto con una **huella SHA-256 de integridad (no es una firma)**.
- **`apply`**: valida el plan (huella, caducidad, zona, duplicados, riesgo, configuración sin cambios) y, por elemento, recalcula las protecciones y compara la identidad y los metadatos. Abre los directorios con `O_NOFOLLOW` componente a componente y mueve con `renameatx_np(RENAME_EXCL)` dentro del mismo volumen. Escribe un manifiesto encadenado con `fsync` y escritura anticipada (`intento` → `movido`).
- **`restore`**: restaura una operación entera o un elemento. Verifica el inodo, los metadatos y el SHA-256, y **nunca sobrescribe**: un conflicto es un error explícito y el fichero sigue en cuarentena.
- **`purge`**: selecciona por antigüedad (14 días, configurable en `[cuarentena].dias`). Solo borra en zona sintética y solo lo que figura en el manifiesto con el inodo correcto.

Requisitos: macOS y Python 3.11 o superior (por `tomllib`). El lanzador elige solo el primer Python
válido (`python3`, `/opt/homebrew/bin/python3`, …), o el que indiques en `MAC_CLEANER_PYTHON`.
No hay dependencias externas. Un escaneo completo tarda unos 14–16 s, con unos 65 MB de RAM, `nice +10`
y E/S en modo *throttle*.

## Qué mide

| Regla | Raíz | Umbral | Riesgo base |
|---|---|---|---|
| `homebrew` | `brew --cache` | 30 d | bajo |
| `pip` | `pip cache dir` | 0 (la gestiona pip) | bajo |
| `npm` | `$npm_config_cache` → `~/.npmrc` → `~/.npm` (npm **no** se ejecuta) | 0 | bajo |
| `logs-usuario` | `~/Library/Logs` | 30 d | bajo |
| `temporales` | `$TMPDIR`, `/private/tmp` (solo ficheros cuyo propietario es el usuario) | 7 d | medio |
| `caches-usuario` | `~/Library/Caches` | 30 d | medio |

Para cada grupo (primer componente bajo la raíz) el informe da:

- **Lógico**: suma de `st_size`.
- **Ocupado (físico)**: `st_blocks × 512`, igual que `du`. Los ficheros dispersos o comprimidos ocupan menos de lo que miden.
- **Antigüedad**: `max(mtime, birthtime)`. Un fichero descargado ayer con un mtime antiguo cuenta como reciente.
- **Última modificación** y antigüedad del fichero más reciente y del más antiguo, con un reparto por tramos (<7 d, 7–30, 30–90, 90 d–1 año, >1 año).
- **Estado**:
  - *en uso*: algún fichero aparece en `lsof`.
  - *activo*: algún fichero es más reciente que el umbral.
  - *inactivo*.
  - *regenerable*: umbral 0, la caché la gestiona su propia herramienta.
- **Riesgo**: el de la regla, elevado por `[[ajuste_riesgo]]`. Por ejemplo, Telegram queda en riesgo alto porque puede contener medios recibidos.

### Ocupado no es recuperable

- **Candidato**: ficheros con antigüedad mayor o igual al umbral y no abiertos. Es una cota superior.
- **Recuperable conservador**: solo grupos enteros *inactivos* o *regenerables*, sin ficheros abiertos y que no sean de riesgo alto.
- Ninguna cifra está garantizada. Los clones de APFS comparten bloques: borrar un clon no libera nada. Si hay snapshots locales, el espacio no se libera hasta que caducan; el informe los lista con `tmutil listlocalsnapshots /`. Además, las cachés se regeneran.

## Seguridad

1. **Poda previa**: las rutas protegidas no se listan ni se les hace `lstat`; se registran como «no inspeccionadas» y su tamaño no se suma. Hay protección en cuatro niveles:
   - **Fija, en el código** (`maccleaner/guards.py`, no se puede desactivar):
     - Perfiles de Claude, Codex y Gemini: `~/.claude*`, `~/.codex`, `~/.gemini`.
     - Credenciales: `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/Library/Keychains`.
     - Carpetas de usuario y datos personales: `~/Documents`, `~/Desktop`, `~/Downloads`, `~/Pictures`, `~/Music`, `~/Movies`, Mail, Messages, iCloud Drive.
     - Datos de apps: Containers, Group Containers, Application Support, Preferences.
     - Sistema y volúmenes: `/Volumes`, `/System`, `/Library`, `/usr`, `/Applications`.
     - Nombres: `claude`, `anthropic`, `argos`, `rea`, `codex`, `gemini`, `antigravity`, `aeon`, `venv`/`.venv`, `keychain`, `.ssh`, `gnupg`.
     - Marcadores: `.git`, `pyvenv.cfg`.
   - **Configurable** (`config/reglas.toml`, solo amplía):
     - Rutas: caché de Claude CLI, Codex, Antigravity, Playwright-MCP y `~/.npm/_npx`.
     - Nombres: modelos (`ollama`, `huggingface`, `gguf`…), producción musical (Ableton, Logic, Avid, SoundFlow…), vídeo y render (Remotion, DaVinci…) y gestores de contraseñas.
     - Extensiones: `.als`, `.logicx`, `.wav`, `.mov`, `.gguf`, `.safetensors`, `.pem`, `.env`…
     - Marcadores de proyecto o entorno: `package.json`, `pyproject.toml`, `Cargo.toml`, `conda-meta`…
2. **Bases permitidas**: una raíz solo se escanea si, tras `realpath`, cae dentro de `~/Library/Caches`, `~/Library/Logs`, `~/.npm`, `$TMPDIR` o `/private/tmp`.
3. **Sin enlaces ni otros volúmenes**: no se siguen enlaces simbólicos y no se cruza a otro `st_dev`. Los enlaces duros se cuentan una vez y las raíces solapadas se reclaman en orden, así que no hay doble conteo.
4. **Guardia de solo lectura** (`maccleaner/guardia.py`, *audit hooks* de Python, PEP 578): se activa al empezar `scan`. Cualquier escritura, borrado, renombrado, `chmod`, `utime`, `mkdir` o *xattr* fuera de `informes/` lanza `PermissionError`, igual que cualquier subproceso fuera de la lista blanca (`lsof`, `tmutil`, `brew`, `pip3`). El informe incluye los subprocesos ejecutados y los intentos bloqueados.
5. **Errores**: un `EPERM` o `EACCES` (TCC, sandbox) se registra y el escaneo continúa.
6. **Sin privilegios**: nunca usa `sudo`.

### Herramientas

- `pip cache dir|info --disable-pip-version-check` y `brew --cache`: comprobado que no modifican nada.
- npm **no se ejecuta**: puede escribir logs en `_logs` en cada orden.
- `brew cleanup -n` es un dry-run, pero en la primera prueba del 14-11 el listado de metadatos de `~/Library/Caches/Homebrew` cambió (causa no determinada; la segunda ejecución no cambió nada). Por eso solo se ejecuta con `--brew-dry-run`.

## Pruebas

```bash
/opt/homebrew/bin/python3 -B -m unittest discover -s tests -v    # 47 pruebas, ~3 s
```

Son 47 pruebas: 16 de F1 (`tests/test_escaner.py`) y 31 de F2 (`tests/test_f2.py`). Todas las de aplicación,
restauración y purga usan solo ficheros ficticios dentro de zonas sintéticas temporales.

**F2** cubre: ciclo completo con restauración exacta (SHA-256, modo, uid, `mtime_ns`, inodo, birthtime y xattr),
restaurar un elemento, planes caducados, futuros o manipulados (huella, rutas fuera de la zona o con `..`, plan «real»,
elementos protegidos inyectados, riesgo alto, duplicados, HOME real), cambios después del escaneo o del plan (contenido,
mtime, contenido con metadatos falsificados), enlace simbólico en lugar del fichero o en un directorio intermedio,
ruta sustituida por otro inodo, abiertos y propietario, error de permisos con aborto, caídas antes y después de mover,
conflictos (fichero existente o directorio desaparecido), integridad del manifiesto (registro editado o eliminado,
sin cierre), purga (retención configurable, solo lo registrado, inodo cambiado), puerta de zona, compatibilidad con F1
(la cuarentena no se escanea; `report` lee los JSON de F1) y la CLI completa con guardia.

**F1** cubre: pruebas sobre un HOME ficticio en un directorio temporal: no modificación (instantánea con SHA-256 y metadatos), exclusiones (registrando cada `lstat` y `scandir`), enlaces simbólicos (externos, en bucle, hacia rutas protegidas, rotos), otro volumen, permisos (`chmod 000`), doble conteo (enlaces duros, reglas solapadas, raíces repetidas), coherencia con `du -sk` (incluido un fichero disperso), antigüedad, ficheros abiertos, riesgo, propietario, herramientas e informe, y la guardia (escrituras y subprocesos bloqueados). Probadas con Python 3.15 y 3.12.

## Estructura

```
mac-cleaner              lanzador (elige Python >= 3.11; -I -B: aislado y sin .pyc)
config/reglas.toml       reglas y protecciones declarativas
maccleaner/guards.py     bases permitidas y protección (fija + configurable)
maccleaner/escaner.py    recorrido de solo lectura (scandir + lstat) y agregados por grupo
maccleaner/guardia.py    guardia de solo lectura en tiempo de ejecución
maccleaner/herramientas.py  localización no destructiva de las cachés de brew, pip y npm
maccleaner/sistema.py    prioridad baja, lsof, disco, snapshots
maccleaner/informe.py    JSON → Markdown
maccleaner/cli.py        órdenes scan, report, plan, apply, restore, purge, oficiales, demo
maccleaner/zona.py       puerta de zona sintética (LIMPIEZA_REAL_HABILITADA = False)
maccleaner/fsseguro.py   openat con O_NOFOLLOW, renameatx_np(RENAME_EXCL), SHA-256 por descriptor
maccleaner/manifiesto.py manifiesto JSON Lines encadenado con fsync
maccleaner/plan.py       creación y validación de planes
maccleaner/aplicar.py    apply (cuarentena)
maccleaner/restaurar.py  restore
maccleaner/purgar.py     selección por antigüedad y purga (solo zona sintética)
maccleaner/oficiales.py  brew, npm y pip: reversibles frente a destructivas
tests/                   pruebas focalizadas (unittest)
informes/                resultados de los escaneos (local, no versionado)
docs/SEGURIDAD-F2.md     modelo de amenazas, metadatos, limitaciones y plan de habilitación real
```
