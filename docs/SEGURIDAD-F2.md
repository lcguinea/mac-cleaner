# mac-cleaner F2 · Seguridad, limitaciones y plan de habilitación

Estado (14-11-2026): `plan`, `apply`, `restore` y `purge` funcionan y están probados **solo sobre datos
ficticios en zonas sintéticas**. La limpieza de datos reales está deshabilitada por la constante
`zona.LIMPIEZA_REAL_HABILITADA = False`; no existe ninguna opción de línea de órdenes que la active.

## 1. Modelo de amenazas cubierto

| Amenaza | Defensa | Prueba |
|---|---|---|
| Plan manipulado (tamaños, rutas, elementos añadidos) | Huella SHA-256 del contenido canónico; además, `apply` revalida todo sin fiarse del plan | `test_huella_rota`, `test_elemento_protegido_inyectado` |
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
| Escritura fuera de la zona por un fallo de código | Guardia de *audit hooks* (PEP 578): en `apply`, `restore` y `purge` solo se puede escribir dentro de la zona | `test_cli_ciclo_completo_con_guardia` (0 bloqueos en uso normal) |

## 2. Transacciones, fallos parciales y trazabilidad

- **Manifiesto** (`<zona>/.mac-cleaner-cuarentena/<op>/manifiesto.jsonl`): JSON Lines con `fsync` por registro y cadena SHA-256 (`prev` → `h`). Detecta registros editados, eliminados o reordenados. Un final truncado no se detecta con la cadena, pero la operación queda «sin cierre» y `purge` no la toca.
- **Escritura anticipada**: `intento` → movimiento → `movido`. Si el proceso muere entre medias, `restore` busca el fichero por inodo en la cuarentena (lo restaura) o en el origen (anota `no_movido`). Pruebas: `test_caida_tras_mover_y_antes_de_registrar` y `test_caida_antes_de_mover`.
- **Comprobación previa fallida**: el elemento se **omite** con su motivo y se sigue con el siguiente.
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

## 4. Purga

- Selección por antigüedad: `[cuarentena].dias = 14` en el TOML, o `purge --dias N`. Mínimo 1 día.
- Solo cuentan operaciones **cerradas**, con manifiesto íntegro, y elementos en estado `movido`.
- `purge` sin `--ejecutar` solo lista.
- Con `--ejecutar` (solo en zona sintética): comprueba el inodo antes de cada borrado, borra solo lo registrado (nunca un `rmtree`; los ficheros ajenos a la cuarentena se respetan) y solo retira directorios vacíos de la propia cuarentena.

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
