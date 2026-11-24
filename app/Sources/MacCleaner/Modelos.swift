import Foundation

/// Documento JSON de `mac-cleaner scan` (solo los campos que muestra la app).
struct Escaneo: Decodable {
    let generado: String
    let disco: Disco?
    let escaneo: Resultado

    struct Disco: Decodable {
        let volumen: String?
        let total: Int64
        let libre: Int64
        let usado: Int64
    }

    struct Resultado: Decodable {
        let reglas: [Regla]
        let contadores: Contadores?
        let duracion_s: Double?
    }

    struct Contadores: Decodable {
        let ficheros: Int?
    }

    struct Regla: Decodable, Identifiable {
        let id: String
        let descripcion: String?
        let riesgo: String?
        let edad_minima_dias: Double?
        let limpieza_oficial: String?
        let totales: Totales
        let n_grupos: Int?
        let grupos: [Grupo]?
    }

    struct Totales: Decodable {
        let ficheros: Int?
        let logico: Int64?
        let fisico: Int64?
        let candidatos_fisico: Int64?
        let abiertos_fisico: Int64?
        let recuperable_conservador: Int64?
    }

    struct Grupo: Decodable, Identifiable {
        var id: String { ruta ?? nombre }
        let nombre: String
        let ruta: String?
        let ficheros: Int?
        let fisico: Int64?
        let candidatos_fisico: Int64?
        let riesgo: String?
        let motivo_riesgo: String?
        let estado: String?
        let recuperable_conservador: Int64?
    }

    var fechaGenerado: Date? {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
        return f.date(from: generado)
    }

    var totalFisico: Int64 { escaneo.reglas.reduce(0) { $0 + ($1.totales.fisico ?? 0) } }
    var totalRecuperable: Int64 { escaneo.reglas.reduce(0) { $0 + ($1.totales.recuperable_conservador ?? 0) } }
    var totalCandidatos: Int64 { escaneo.reglas.reduce(0) { $0 + ($1.totales.candidatos_fisico ?? 0) } }
}

/// Salida de `mac-cleaner autorizacion`.
struct Autorizacion: Decodable {
    let id: String
    let fecha: String
    let texto: String
    let reglas: [String]
    let max_bytes: Int64
    let dias_cuarentena: Int
    let ventana: [String]?
    let vigente: Bool
    let purga_real: Bool
    let requiere_ventana: Bool?

    func autoriza(_ regla: String) -> Bool { vigente && reglas.contains(regla) }
}

/// Salida de `mac-cleaner limpiar --vista-previa`.
struct VistaPrevia: Decodable {
    struct Seleccion: Decodable {
        let ficheros: Int
        let bytes: Int64
        let grupos: [Grupo]
    }

    struct Grupo: Decodable, Identifiable {
        var id: String { grupo }
        let grupo: String
        let ficheros: Int
        let bytes: Int64
        let riesgo: String
    }

    let autorizacion: String
    let reglas: [String: Seleccion]
    let omitidas: [String: String]
    let total_bytes: Int64
    let total_ficheros: Int
    let max_bytes: Int64
    let supera_tope: Bool
    let bloqueada: String?
    let dias_cuarentena: Int
    let sombra: String
}

/// Salida de `mac-cleaner limpiar --ejecutar`.
struct ResultadoLimpieza: Decodable {
    let op: String
    let movidos: Int
    let omitidos: Int
    let errores: Int
    let bytes_movidos: Int64
    let abortado: String?
    let reglas: [String]
    let omitidas: [String: String]
}

/// Salida de `mac-cleaner purge --real --ejecutar`.
struct ResultadoPurga: Decodable {
    let borrados: Int?
    let errores: Int?
    let bytes: Int64
    let ejecutado: Bool
}

/// Nombre y símbolo de cada regla del motor.
enum Categoria {
    static func nombre(_ id: String) -> String {
        switch id {
        case "homebrew": return "Homebrew"
        case "pip": return "Caché de pip"
        case "npm": return "Caché de npm"
        case "logs-usuario": return "Registros de apps"
        case "temporales": return "Archivos temporales"
        case "caches-usuario": return "Cachés de apps"
        default: return id
        }
    }

    static func simbolo(_ id: String) -> String {
        switch id {
        case "homebrew": return "mug"
        case "pip": return "shippingbox"
        case "npm": return "cube.box"
        case "logs-usuario": return "doc.text.magnifyingglass"
        case "temporales": return "clock.arrow.circlepath"
        case "caches-usuario": return "internaldrive"
        default: return "folder"
        }
    }
}
