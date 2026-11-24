import Foundation

/// Puente con el motor Python de mac-cleaner (copiado dentro de la app en Contents/Resources/motor).
/// La app NUNCA decide por su cuenta qué se limpia: escanear, autorizar, mover a cuarentena y restaurar
/// son órdenes del motor, con todas sus protecciones.
enum ErrorMotor: LocalizedError {
    case noEncontrado
    case fallo(codigo: Int32, mensaje: String)
    case salidaInesperada(String)

    var errorDescription: String? {
        switch self {
        case .noEncontrado:
            return "No se encuentra el motor de mac-cleaner dentro de la app."
        case let .fallo(codigo, mensaje):
            return mensaje.isEmpty ? "El motor terminó con el código \(codigo)." : mensaje
        case let .salidaInesperada(s):
            return "Respuesta inesperada del motor: \(s.prefix(300))"
        }
    }
}

struct ResultadoMotor {
    let codigo: Int32
    let salida: String
    let errores: String
}

enum Motor {
    /// Lanzador del motor: el de la app o, en desarrollo, MAC_CLEANER_MOTOR.
    static var lanzador: URL? {
        let fm = FileManager.default
        if let env = ProcessInfo.processInfo.environment["MAC_CLEANER_MOTOR"], fm.isExecutableFile(atPath: env) {
            return URL(fileURLWithPath: env)
        }
        if let r = Bundle.main.resourceURL?.appendingPathComponent("motor/mac-cleaner"), fm.isExecutableFile(atPath: r.path) {
            return r
        }
        return nil
    }

    /// ~/Library/Application Support/Mac Cleaner
    static var soporte: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("Mac Cleaner", isDirectory: true)
    }

    static var informes: URL { soporte.appendingPathComponent("informes", isDirectory: true) }

    static var cuarentena: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".mac-cleaner/cuarentena", isDirectory: true)
    }

    static func ejecutar(_ argumentos: [String]) async throws -> ResultadoMotor {
        guard let lanzador else { throw ErrorMotor.noEncontrado }
        return try await withCheckedThrowingContinuation { cont in
            DispatchQueue.global(qos: .userInitiated).async {
                let p = Process()
                p.executableURL = lanzador
                p.arguments = argumentos
                var entorno = ProcessInfo.processInfo.environment
                // Las apps arrancan con un PATH mínimo: el motor necesita encontrar Python, brew, pip y lsof.
                entorno["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
                p.environment = entorno
                let out = Pipe(), err = Pipe()
                p.standardOutput = out
                p.standardError = err
                p.standardInput = FileHandle.nullDevice
                do {
                    try p.run()
                } catch {
                    cont.resume(throwing: error)
                    return
                }
                var datosErr = Data()
                let grupo = DispatchGroup()
                grupo.enter()
                DispatchQueue.global().async {
                    datosErr = err.fileHandleForReading.readDataToEndOfFile()
                    grupo.leave()
                }
                let datosOut = out.fileHandleForReading.readDataToEndOfFile()
                grupo.wait()
                p.waitUntilExit()
                cont.resume(returning: ResultadoMotor(codigo: p.terminationStatus,
                                                      salida: String(decoding: datosOut, as: UTF8.self),
                                                      errores: String(decoding: datosErr, as: UTF8.self)))
            }
        }
    }

    /// `scan --salida <Application Support>/informes`: devuelve la ruta del JSON generado.
    static func escanear() async throws -> URL {
        try FileManager.default.createDirectory(at: informes, withIntermediateDirectories: true)
        let r = try await ejecutar(["scan", "--salida", informes.path])
        guard r.codigo == 0 else {
            throw ErrorMotor.fallo(codigo: r.codigo, mensaje: r.errores.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        guard let linea = r.salida.split(separator: "\n").first(where: { $0.hasPrefix("JSON: ") }) else {
            throw ErrorMotor.salidaInesperada(r.salida)
        }
        return URL(fileURLWithPath: String(linea.dropFirst("JSON: ".count)))
    }

    static func ultimoEscaneo() -> URL? {
        let fm = FileManager.default
        guard let nombres = try? fm.contentsOfDirectory(atPath: informes.path) else { return nil }
        let escaneos = nombres.filter { $0.hasPrefix("scan-") && $0.hasSuffix(".json") }.sorted()
        return escaneos.last.map { informes.appendingPathComponent($0) }
    }

    static func autorizacion() async throws -> Autorizacion {
        let r = try await ejecutar(["autorizacion"])
        guard r.codigo == 0 else {
            throw ErrorMotor.fallo(codigo: r.codigo, mensaje: r.errores.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        do {
            return try JSONDecoder().decode(Autorizacion.self, from: Data(r.salida.utf8))
        } catch {
            throw ErrorMotor.salidaInesperada(r.salida)
        }
    }

    private static func decodificar<T: Decodable>(_ tipo: T.Type, _ r: ResultadoMotor, aceptar: Set<Int32> = [0]) throws -> T {
        guard aceptar.contains(r.codigo) else {
            throw ErrorMotor.fallo(codigo: r.codigo, mensaje: r.errores.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        do {
            return try JSONDecoder().decode(T.self, from: Data(r.salida.utf8))
        } catch {
            if !r.errores.isEmpty {
                throw ErrorMotor.fallo(codigo: r.codigo, mensaje: r.errores.trimmingCharacters(in: .whitespacesAndNewlines))
            }
            throw ErrorMotor.salidaInesperada(r.salida)
        }
    }

    /// F5B paso 1: escaneo + sombra. Solo lectura; no usa la clave.
    static func vistaPrevia() async throws -> VistaPrevia {
        try decodificar(VistaPrevia.self, try await ejecutar(["limpiar", "--vista-previa"]))
    }

    /// F5B paso 2: plan real firmado + apply en un solo proceso (macOS pide permiso para la clave una vez).
    static func limpiar(hastaBytes: Int64, reglas: [String]) async throws -> ResultadoLimpieza {
        var args = ["limpiar", "--ejecutar", "--hasta-bytes", String(hastaBytes)]
        for r in reglas { args += ["--regla", r] }
        // Código 1 = terminó con omisiones, errores o aborto: el JSON sigue siendo válido y se muestra.
        return try decodificar(ResultadoLimpieza.self, try await ejecutar(args), aceptar: [0, 1])
    }

    /// Purga real de lo que lleve en cuarentena al menos los días autorizados.
    static func purgar() async throws -> ResultadoPurga {
        try decodificar(ResultadoPurga.self, try await ejecutar(["purge", "--real", "--ejecutar"]), aceptar: [0, 1])
    }

    /// `restore --real --operacion OP`. macOS pedirá permiso para leer la clave HMAC del Llavero.
    static func restaurar(operacion: String) async throws -> ResultadoMotor {
        try await ejecutar(["restore", "--real", "--operacion", operacion])
    }
}
