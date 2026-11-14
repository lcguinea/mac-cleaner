# mac-cleaner F2 · Seguridad, limitaciones y plan de habilitación

Estado (14-11-2026): `plan`, `apply`, `restore` y `purge` funcionan y están probados **solo sobre datos
ficticios en zonas sintéticas**. La auditoría F2.5 (§8) encontró y corrigió 14 defectos; ninguna de estas garantías
es absoluta: los riesgos que siguen abiertos están en §6 y §8.3. La limpieza de datos reales está deshabilitada por la constante
`zona.LIMPIEZA_REAL_HABILITADA = False`; no existe ninguna opción de línea de órdenes que la active.

## 1. Modelo de amenazas cubierto

| Amenaza | Defensa | Prueba |
|---|---|---|
| Plan manipulado (tamaños, rutas, elementos añadidos) | Huella SHA-256 del contenido canónico; además, `apply` revalida todo sin fiarse del plan | `test_huella_rota`, `test_elemento_protegido_inyectado` |
| Plan forjado que rebaja riesgo, antigüedad o regla (F2.5) | `apply` recalcula regla, grupo, riesgo (`[[ajuste_riesgo]]`) y antigüedad mínima con la configuración verificada; la ruta debe colgar de una raíz de su regla | `test_plan_forjado_no_puede_rebajar_riesgo_ni_antiguedad`, `test_plan_forjado_con_regla_inexistente` |
| Plan con tipos inesperados (F2.5) | Validación estricta de tipos (enteros no negativos, texto, SHA-256 hexadecimal, riesgo bajo/medio) | `test_tipos_no_validos_en_el_plan` |
| Reproducir un plan ya aplicado y restaurado | El rename cambia ctime: `apply` lo detecta como «modificado después del plan» | `test_reproducir_un_plan_tras_restaurar_no_vuelve_a_mover` |
| Huella recalculada por un atacante | La huella **no es una firma**. Lo que protege es la revalidación: zona, protecciones, metadatos e inodo | `test_ruta_fuera_de_la_zona_o_real`, `test_riesgo_alto_duplicados_y_campos` |
| Plan o escaneo caducado o con fecha futura | Escaneo ≤ 24 h para planificar; plan ≤ 24 h (y no alargable) para aplicar; tolerancia de 5 min al futuro | `test_escaneo_caducado_o_futuro`, `test_caducado_y_futuro` |
| Configuración cambiada entre escaneo, plan y apply | Huella del TOML en el escaneo y en el plan; si cambia, se rechaza | `test_configuracion_cambiada_desde_el_escaneo` |
| Fichero modificado después del escaneo | `plan` vuelve a recorrer el grupo AHORA (antigüedad, lsof) | `test_modificado_despues_del_escaneo_reevalua_el_grupo` |
| Fichero modificado después del plan | `apply` compara tamaño, mtime_ns, ctime_ns y SHA-256 | `test_fichero_modificado_tras_el_plan`, `test_contenido_cambiado_con_metadatos_falsificados` |
| Enlace simbólico en lugar del fichero | `lstat` sin seguir enlaces + exigir fichero regular con el mismo inodo | `test_enlace_simbolico_en_lugar_del_fichero` |
| Directorio intermedio sustituido por un enlace | Apertura componente a componente con `O_NOFOLLOW|O_DIRECTORY` (openat) y `RENAME_NOFOLLOW_ANY` | `test_directorio_intermedio_sustituido_por_enlace` |
| Ruta sustituida por otro fichero idéntico | Identidad `(st_dev, st_ino)`; tras mover se vuelve a comprobar en el destino y, si no coincide, se devuelve | `test_ruta_sustituida_por_otro_fichero` |
| Fichero abierto o de otro propietario | lsof al empezar `apply` y uid = usuario | `test_abierto_o_de_otro_propietario` |
| Sobrescritura al mover o restaurar | `renameatx_np(RENAME_EXCL)`: el destino existente da EEXIST, nunca se pisa | `test_conflicto_con_fichero_existente` |
| Perfiles de desarrollo y datos protegidos | Las protecciones de F1 (fijas y del TOML) se recalculan por elemento, incluidos los marcadores de proyecto o entorno en cualquier antepasado | `test_plan_solo_incluye_lo_admisible`, `test_elemento_protegido_inyectado` |
| Operación sobre datos reales | Puerta de zona sintética: ruta canónica bajo `$TMPDIR` o `/private/tmp` (sin ser esa raíz), fuera del HOME, del usuario, no escribible por otros y con marcador exacto | `TestZona.test_puerta_de_zona`, `test_cli_ciclo_completo_con_guardia` |
| Escritura fuera de la zona por un fallo de código | Guardia de *audit hooks* (PEP 578): en `apply`, `restore` y `purge` solo se puede escribir dentro de la zona; las rutas relativas a un descriptor (`unlinkat`, `mkdirat`, `rmdirat`) se resuelven con `F_GETPATH` | `test_cli_ciclo_completo_con_guardia`, `test_guardia_resuelve_rutas_relativas_a_un_descriptor`, `test_purga_ejecutada_por_la_cli_con_la_guardia_activa` (0 bloqueos en uso normal) |
| Dos procesos sobre la misma operación (F2.5) | `flock` exclusivo del manifiesto en `apply`, `restore` y `purge`, con recarga al obtenerlo; `anotar` se niega a escribir si el fichero cambió desde que lo leyó | `test_escrituras_concurrentes_no_corrompen_el_manifiesto`, `test_operacion_bloqueada_rechaza_restore_y_purge`, `test_purga_relee_el_manifiesto_bajo_bloqueo` |
| Cuarentena o manifiesto manipulados (F2.5) | Cuarentena del usuario y sin escritura de grupo ni otros (cada componente); directorios creados con `mkdirat`; manifiesto abierto con `O_NOFOLLOW` | `test_cuarentena_preexistente_con_permisos_abiertos`, `test_asegurar_dir_no_crea_directorios_a_traves_de_enlaces`, `test_manifiesto_sustituido_por_enlace` |

## 2. Transacciones, fallos parciales y trazabilidad

- **Manifiesto** (`<zona>/.mac-cleaner-cuarentena/<op>/manifiesto.jsonl`): JSON Lines con `fsync` por registro y cadena SHA-256 (`prev` → `h`). Detecta registros editados, eliminados o reordenados. Un final truncado no se detecta con la cadena, pero la operación queda «sin cierre» y `purge` no la toca.
- **Escritura anticipada**: `intento` → movimiento → `movido`. Si el proceso muere entre medias, `restore` busca el fichero por inodo en la cuarentena (lo restaura) o en el origen (anota `no_movido`). Pruebas: `test_caida_tras_mover_y_antes_de_registrar` y `test_caida_antes_de_mover`.
- **Comprobación previa fallida**: el elemento se **omite** con su motivo y se sigue con el siguiente.
- **Sustitución detectada al mover**: si el objeto que llegó a la cuarentena no es el planificado, se devuelve a su sitio. Si el origen ya está ocupado, el objeto ajeno queda **retenido** y registrado (`sustitucion_no_revertida`); la operación sigue y ese objeto no se restaura ni se purga automáticamente. Prueba: `test_sustitucion_que_no_se_puede_revertir_no_aborta_ni_pierde_rastro`.
- **Bloqueo**: toda la operación se hace con el manifiesto bloqueado (`flock`, sin espera). Un `restore` o `purge` simultáneo de la misma operación se rechaza («operación ocupada»).
- **Error del sistema al mover** (EACCES, EIO…): se **aborta** el resto, se registra `abortado` y `cierre`, y lo ya movido es restaurable. Prueba: `test_error_de_permisos_aborta_sin_perder_nada`.
- **Cuarentena en el mismo volumen**: si el `st_dev` difiere, se omite. Nunca se copia ni se borra para «mover» entre volúmenes.

## 3. Restauración: qué se conserva y qué no

Mover y restaurar son `rename` dentro del mismo volumen: **es el mismo inodo**.

| Se conserva exactamente (verificado en pruebas) | No se conserva |
|---|---|
| Contenido (SHA-256) | `ctime`: el kernel lo actualiza en cada rename |
| Modo y permisos, propietario | `mtime` y `ctime` de los directorios padre (cambian al salir y volver una entrada) |
| `mtime_ns` y `birthtime` | Fecha de añadido de Finder (`kMDItemDateAdded`): se recalcula al llegar la entrada |
| Atributos extendidos (verificado con `xattr`); por ser el mismo inodo, también ACL y flags | Si se eliminó el directorio de destino, no se recrea: es un conflicto explícito |
| Número de inodo | |

`restore` nunca sobrescribe. Si el destino existe, o su directorio no existe o no es seguro, devuelve un **conflicto** explícito, deja el fichero en cuarentena y se puede reintentar.

Desde F2.5:

- Un **error** al restaurar un elemento (permisos, E/S, contenido alterado) se registra como `restaurar_error` sin cambiar su estado: el fichero sigue en cuarentena y otro `restore` lo reintenta. Prueba: `test_error_transitorio_permite_reintentar`.
- Si un `restore` anterior murió después de devolver el fichero y antes de anotarlo, el reintento lo localiza por inodo en el origen y lo anota como restaurado. Prueba: `test_caida_durante_restore_despues_de_mover`.
- **Ficheros grandes** (más de `hash_max_mb`, sin SHA-256): `apply` registra su ctime al entrar en la cuarentena; si al restaurar no coincide, alguien los tocó (contenido, permisos o atributos aunque la mtime se restituyera con `utime`) y no se devuelven. Prueba: `test_fichero_grande_sin_hash_se_restaura_y_se_detecta_su_alteracion` (80 MB dispersos).

## 4. Purga

- Selección por antigüedad: `[cuarentena].dias = 14` en el TOML, o `purge --dias N`. Mínimo 1 día en ambos casos (antes de F2.5, `--dias 0` se aceptaba).
- Solo cuentan operaciones **cerradas**, con manifiesto íntegro, y elementos en estado `movido`.
- `purge` sin `--ejecutar` solo lista.
- Con `--ejecutar` (solo en zona sintética): bloquea cada operación y relee su manifiesto (si está ocupada, la salta; solo borra lo que **sigue** `movido`), comprueba el inodo y borra con `unlinkat` sobre el **mismo descriptor** de directorio con el que lo comprobó. Borra solo lo registrado (nunca un `rmtree`; los ficheros ajenos a la cuarentena se respetan) y retira directorios vacíos de la propia cuarentena con `fwalk` + `rmdirat`, sin seguir enlaces.

## 5. Herramientas oficiales (`mac-cleaner oficiales`)

| Herramienta | Reversible (consulta o cuarentena) | Destructiva (no se ejecuta) |
|---|---|---|
| Homebrew | `brew --cache`; `brew cleanup -n` (opcional); mover la caché a cuarentena | `brew cleanup` (borra también versiones antiguas del **Cellar**, fuera de la caché), `brew autoremove` |
| npm | leer `$npm_config_cache` y `~/.npmrc`; mover `_cacache` a cuarentena | `npm cache clean --force`, **`npm cache verify`** (parece una consulta, pero borra) |
| pip | `pip cache dir|info`; mover la caché a cuarentena | `pip cache purge`, `pip cache remove` |

Recomendación: para las tres, la vía reversible es mover su caché con `plan` y `apply`. Las herramientas la regeneran al necesitarla, y `restore` la devuelve. Las órdenes oficiales quedan como alternativa irreversible y requerirían una autorización explícita aparte.

## 6. Limitaciones conocidas

- **ctypes y la guardia**: el movimiento usa `renameatx_np` mediante ctypes, que no emite eventos de auditoría. La guardia no lo ve. Lo protegen la validación de rutas dentro de la zona y los descriptores `O_NOFOLLOW`.
- **Ventana TOCTOU residual**: entre el último `stat` y el `rename` alguien podría cambiar el fichero. La verificación del inodo en destino lo detecta y lo devuelve. Un cambio de **contenido** del mismo inodo en esa ventana no se detecta; sería el contenido «nuevo» el que va a cuarentena, sin pérdida.
- **Ventana residual en `purge`**: entre `fstatat` y `unlinkat` (mismo descriptor) otro proceso del usuario podría renombrar otra entrada al mismo nombre **dentro del mismo directorio de la cuarentena** (0700). macOS no tiene un `unlink` condicionado al inodo. Fuera de la cuarentena ya no es alcanzable.
- **`flock` es cooperativo**: protege frente a otras ejecuciones de mac-cleaner, no frente a un proceso que escriba el manifiesto sin pedir el bloqueo.
- **ctime de ficheros grandes**: cualquier cambio de metadatos (por ejemplo, un *xattr* añadido por el sistema) también cambia el ctime; `restore` lo trata como alteración y no devuelve el fichero. Es un falso positivo seguro: el fichero sigue en cuarentena para revisión manual.
- **Manifiesto con la última línea truncada** (corte de luz a mitad de escritura): se rechaza entero. Los ficheros siguen en la cuarentena con la misma estructura de rutas, pero la recuperación sería manual.
- **Ficheros sin hash**: los mayores de `hash_max_mb` (64 MB) se verifican solo por inodo, tamaño, mtime y ctime.
- **Enlaces duros**: se excluyen del plan, porque moverlos no libera espacio.
- **Escala**: máximo 200 000 elementos por plan; el plan guarda una entrada por fichero (npm ≈ 16 700 ficheros generaría un JSON de varios MB).
- **Huella**: es solo de integridad. Una firma real (HMAC con clave en el Llavero) sería una mejora para F3.
- **lsof**: instantánea al inicio de `apply`. Un fichero que se abra después no se detecta.
- **Clones de APFS y snapshots**: mover a cuarentena no libera espacio hasta purgar. Con clones o snapshots, ni siquiera la purga libera nada.

## 7. Plan de habilitación de limpiezas reales (requiere autorización explícita)

Ninguno de estos pasos se ha hecho. Cada uno es una decisión del usuario, con su prueba previa.

1. **Decisión escrita** de qué reglas se habilitan. Propuesta inicial: solo `npm` (`_cacache`) y `pip`, riesgo bajo y regenerables.
2. **Cuarentena real**: `~/.mac-cleaner/cuarentena/` (ya protegida en `guards.py`), en el mismo volumen que `~/Library/Caches` y `~/.npm`. Comprobación de `st_dev` por elemento, como en F2.
3. **Cambio de código revisable**: sustituir la constante por una **lista blanca de reglas** (no un interruptor general), mantener la puerta de zona para todo lo demás y añadir firma HMAC del plan con clave en el Llavero.
4. **Ensayo en sombra**: `plan` real con `--hash` durante una semana, sin `apply`, revisando las exclusiones.
5. **Primera ejecución acompañada**: `apply` de una sola regla con el usuario delante; `restore` completo inmediato como simulacro; después, `apply` definitivo.
6. **Retención**: 14 días antes de que `purge --ejecutar` pueda actuar fuera de zonas sintéticas. Esto exigirá una segunda autorización.
7. **Programación (launchd)**: solo después, y solo para `scan` + `plan` (informes). Nunca `apply` desatendido sin otra decisión expresa.

## 8. Auditoría F2.5 (14-11-2026)

Alcance: `fsseguro`, `aplicar`, `restaurar`, `purgar`, `manifiesto`, `plan`, `guardia`, `zona` y las protecciones de F1
aplicadas en F2. Cada defecto se reprodujo con una prueba que **fallaba** sobre `4b850ea` y pasa con la corrección
(`tests/test_f25.py`). Todo con ficheros ficticios en zonas sintéticas; ningún dato real se movió ni se borró.

Clasificación: **V** = vulnerabilidad demostrada (un tercero con acceso de escritura a la zona, al plan o al manifiesto,
o una carrera, produce un efecto indebido sobre ficheros); **R** = defecto de robustez demostrado (fallo, pérdida de
trazabilidad o recuperación imposible con la herramienta, sin borrar datos ajenos).

### 8.1 Defectos encontrados y corregidos

| # | Tipo | Gravedad | Defecto y evidencia | Corrección |
|---|---|---|---|---|
| D1 | V | Alta | `purge` comprobaba el inodo por descriptor y luego borraba **por ruta**. Si se cambia un directorio intermedio de la cuarentena por un enlace entre ambas cosas, borraba un fichero ajeno (la prueba borró `victima/…/a.bin`). Fuera de la zona lo paraba la guardia; con una cuarentena real habría sido grave | `unlinkat` sobre el mismo descriptor verificado; directorios vacíos con `fwalk` + `rmdirat` |
| D8 | V | Alta | `apply` se fiaba del `riesgo`, la `regla` y la `edad_minima_dias` del plan. Un plan con la huella recalculada movió un fichero de Telegram (riesgo alto por `[[ajuste_riesgo]]`), uno recién modificado y uno fuera de las raíces de su regla. Contradecía «apply revalida todo» | Regla, grupo, riesgo y antigüedad se recalculan con la configuración verificada |
| D4 | R | Media-alta | Dos procesos sobre la misma operación (dos `restore`, o `restore` y `purge`) escribían registros con el mismo número y rompían la cadena. Después, `restore` rechazaba el manifiesto y la operación ya no se podía recuperar con la herramienta. `purge` decidía además con una selección vieja | `flock` exclusivo con recarga; `anotar` comprueba el tamaño conocido; `purge` relee bajo bloqueo |
| D14 | V/R | Media | La guardia resolvía las rutas relativas contra el cwd e ignoraba `dir_fd`: bloqueaba operaciones legítimas por descriptor y, con el cwd dentro de la zona, habría dejado pasar un `unlinkat` hacia fuera | Resolución con `fcntl(F_GETPATH)` del descriptor |
| D2 | V | Media | `purge --dias 0 --ejecutar` (o negativo) borraba sin retención; el mínimo de 1 día solo se aplicaba en el TOML | `seleccionar` exige ≥ 1 día; la CLI devuelve 2 |
| D3 | R | Media | Un error pasajero en `restore` (p. ej. permisos) dejaba el elemento en estado `error`. Ningún `restore` posterior lo reintentaba y `purge` tampoco lo tocaba: el fichero quedaba atrapado | `restaurar_error` no cambia el estado |
| D5 | V | Media | `anotar` abría el manifiesto siguiendo enlaces: un enlace en su lugar recibía los registros fuera de la cuarentena | `O_NOFOLLOW` al leer y al escribir; fichero regular obligatorio |
| D6 | R | Media | Si `restore` moría tras devolver el fichero y antes de anotarlo, el reintento daba error y el manifiesto seguía diciendo `movido` | Búsqueda por inodo en el origen y anotación como restaurado |
| D7 | V | Media | En ficheros sin SHA-256 (> 64 MB), un cambio de contenido en la cuarentena con la mtime restituida (`utime`) no se detectaba al restaurar | ctime registrado en `movido` y comparado en `restore` |
| D9 | R | Baja-media | Si al devolver un objeto sustituido el origen estaba ocupado, la excepción abortaba toda la operación y el objeto ajeno quedaba en la cuarentena sin registro | Registro `sustitucion_no_revertida`, estado `retenido` y la operación continúa |
| D12 | V | Baja | Una cuarentena creada antes por otro proceso con permisos 0777 se aceptaba | Cada componente debe ser del usuario y no escribible por grupo ni otros (`DirectorioInseguro`) |
| D13 | V | Baja | `asegurar_dir` creaba con `mkdir` por ruta: un enlace intermedio hacía crear directorios (vacíos) fuera | `mkdirat` relativo al descriptor del padre |
| D10 | R | Baja | Tipos inesperados en el plan (`"creado": "ayer"`, `"ruta": 123`…) provocaban `ValueError`/`TypeError` internos en lugar de un rechazo | Validación estricta de tipos y valores |
| D11 | R | Baja | Un `destino` forjado igual a la raíz de la cuarentena interrumpía la purga con `ValueError` | El error se registra por elemento y la purga sigue |

### 8.2 Verificado sin defecto

- Protecciones de F1 en `apply`: `motivo_ruta` comprueba **cada componente** relativo a la base (no solo el nombre final), además de los marcadores de proyecto en todos los antepasados. Los perfiles de Claude, Codex, Gemini, Argos, REA y AEON, los proyectos y las credenciales inyectados en un plan se omiten (`test_elemento_protegido_inyectado`).
- Reproducción de un plan: un plan ya aplicado y restaurado no vuelve a mover nada (cambia el ctime).
- Enlaces duros: excluidos en `plan` y rechazados en `apply` (`nlink = 1`).
- Puerta de zona y `LIMPIEZA_REAL_HABILITADA = False`: sin cambios. Un plan sin zona sigue rechazándose por la CLI.
- F1: las 16 pruebas pasan y un escaneo real de solo lectura, tras los cambios, da cifras idénticas en Homebrew y coherentes en el resto (diferencias por actividad normal entre ambos escaneos), con 0 bloqueos de la guardia.

### 8.3 Riesgos que siguen abiertos

- **Teóricos**: la ventana de `purge` dentro del mismo directorio de la cuarentena (§6), el cambio de contenido del mismo inodo durante `apply` (§6) y un proceso que ignore el `flock`.
- **Autenticidad**: la huella del plan y la cadena del manifiesto son de integridad. Quien pueda escribirlos puede recalcularlas. Con un manifiesto forjado se puede redirigir `restore` a otra ruta **dentro de la zona** (nunca sobrescribe) o pedir a `purge` que borre otro fichero **de la cuarentena de esa operación** con el inodo coincidente. Solución prevista: HMAC con clave en el Llavero (§7.3).
- **Aceptadas**: instantánea única de lsof, ficheros grandes verificados por metadatos y ctime (no por contenido) y falsos positivos de ctime (§6).
