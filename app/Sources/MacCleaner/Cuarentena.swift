import AppKit
import SwiftUI

/// Operaciones de la cuarentena real (~/.mac-cleaner/cuarentena). La app solo LEE los manifiestos; restaurar es
/// siempre una orden del motor (verifica la firma HMAC y el contenido de cada fichero).
struct OperacionCuarentena: Identifiable {
    let id: String
    let fecha: Date?
    let autorizacion: String
    let elementos: Int
    let movidos: Int
    let restaurados: Int
    let bytes: Int64
    let reglas: [String]

    var pendientes: Int { max(0, movidos - restaurados) }

    func purgableDesde(dias: Int) -> Date? { fecha?.addingTimeInterval(Double(dias) * 86400) }
}

enum LectorCuarentena {
    static func operaciones() -> [OperacionCuarentena] {
        let fm = FileManager.default
        let base = Motor.cuarentena
        guard let nombres = try? fm.contentsOfDirectory(atPath: base.path) else { return [] }
        var res: [OperacionCuarentena] = []
        for op in nombres.sorted(by: >) where op != "planes-aplicados" && op != "informes" {
            let man = base.appendingPathComponent(op).appendingPathComponent("manifiesto.jsonl")
            guard let texto = try? String(contentsOf: man, encoding: .utf8) else { continue }
            var fecha: Date?, autorizacion = "", elementos = 0, movidos = 0, restaurados = 0
            var reglas: [String] = []
            for linea in texto.split(separator: "\n") {
                guard let o = try? JSONSerialization.jsonObject(with: Data(linea.utf8)) as? [String: Any],
                      let ev = o["evento"] as? String else { continue }
                switch ev {
                case "inicio":
                    if let t = o["ahora"] as? Double { fecha = Date(timeIntervalSince1970: t) }
                    autorizacion = o["autorizacion"] as? String ?? ""
                    elementos = o["n_elementos"] as? Int ?? 0
                    if let lb = o["lista_blanca"] as? [String: Any], let s = lb["subarboles"] as? [String: Any] {
                        reglas = s.keys.sorted()
                    }
                case "movido": movidos += 1
                case "restaurado": restaurados += 1
                default: break
                }
            }
            res.append(OperacionCuarentena(id: op, fecha: fecha, autorizacion: autorizacion, elementos: elementos,
                                           movidos: movidos, restaurados: restaurados,
                                           bytes: tamano(base.appendingPathComponent(op).appendingPathComponent("archivos")),
                                           reglas: reglas))
        }
        return res
    }

    static func tamano(_ dir: URL) -> Int64 {
        guard let e = FileManager.default.enumerator(at: dir, includingPropertiesForKeys: [.totalFileAllocatedSizeKey],
                                                     options: [], errorHandler: { _, _ in true }) else { return 0 }
        var t: Int64 = 0
        while let u = e.nextObject() as? URL {
            t += Int64((try? u.resourceValues(forKeys: [.totalFileAllocatedSizeKey]))?.totalFileAllocatedSize ?? 0)
        }
        return t
    }
}

@MainActor
final class CuarentenaModelo: ObservableObject {
    @Published var operaciones: [OperacionCuarentena] = []
    @Published var restaurando: String?
    @Published var mensaje: String?
    @Published var dias = 14
    @Published var purgaAutorizada = false
    @Published var purgando = false

    var caducadas: [OperacionCuarentena] {
        operaciones.filter { op in op.pendientes > 0 && (op.purgableDesde(dias: dias).map { $0 <= Date() } ?? false) }
    }

    func purgar() async {
        purgando = true
        mensaje = nil
        defer { purgando = false }
        do {
            let r = try await Motor.purgar()
            mensaje = "Purgado: \(r.borrados ?? 0) ficheros borrados definitivamente (\(Formato.bytes(r.bytes)))" +
                ((r.errores ?? 0) > 0 ? " · \(r.errores ?? 0) errores: lo que falló sigue en la cuarentena." : ".")
        } catch {
            mensaje = error.localizedDescription
        }
        cargar()
    }

    func cargar() {
        Task.detached(priority: .utility) {
            let ops = LectorCuarentena.operaciones()
            let a = try? await Motor.autorizacion()
            await MainActor.run {
                self.operaciones = ops
                if let a {
                    self.dias = a.dias_cuarentena
                    self.purgaAutorizada = a.purga_real
                }
            }
        }
    }

    func restaurar(_ op: OperacionCuarentena) async {
        restaurando = op.id
        mensaje = nil
        defer { restaurando = nil }
        do {
            let r = try await Motor.restaurar(operacion: op.id)
            if let o = try? JSONSerialization.jsonObject(with: Data(r.salida.utf8)) as? [String: Any] {
                let n = { (k: String) -> Int in (o[k] as? [Any])?.count ?? (o[k] as? Int) ?? 0 }
                mensaje = "Restaurados: \(n("restaurados")) · conflictos: \(n("conflictos")) · errores: \(n("errores"))." +
                    (n("conflictos") + n("errores") > 0 ? " Lo que no se restauró sigue en la cuarentena; puedes reintentarlo." : "")
            } else {
                let t = (r.errores.isEmpty ? r.salida : r.errores).trimmingCharacters(in: .whitespacesAndNewlines)
                mensaje = r.codigo == 0 ? "Restauración terminada." : "No se pudo restaurar: \(t.prefix(400))"
            }
        } catch {
            mensaje = error.localizedDescription
        }
        cargar()
    }
}

struct CuarentenaView: View {
    @StateObject private var m = CuarentenaModelo()
    @State private var confirmar: OperacionCuarentena?
    @State private var confirmarPurga = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HStack(alignment: .firstTextBaseline) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Cuarentena").font(.largeTitle.bold())
                        Text("Lo que limpia mac-cleaner no se borra: se guarda aquí \(m.dias) días y puedes devolverlo a su sitio.")
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button {
                        m.cargar()
                    } label: {
                        Label("Actualizar", systemImage: "arrow.clockwise")
                    }
                }
                if let t = m.mensaje {
                    Label(t, systemImage: "info.circle")
                        .padding(10)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8))
                }
                if m.operaciones.isEmpty {
                    VStack(spacing: 10) {
                        Image(systemName: "tray").font(.system(size: 40)).foregroundStyle(.tint)
                        Text("La cuarentena está vacía").foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 60)
                }
                if m.purgaAutorizada && !m.caducadas.isEmpty {
                    let bytes = m.caducadas.reduce(Int64(0)) { $0 + $1.bytes }
                    HStack(spacing: 12) {
                        Image(systemName: "clock.badge.checkmark").font(.title2).foregroundStyle(.orange)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("\(m.caducadas.count) operación\(m.caducadas.count == 1 ? "" : "es") con \(m.dias) días o más").font(.headline)
                            Text("Purgar libera \(Formato.bytes(bytes)) y ya no se podrá restaurar.").font(.callout).foregroundStyle(.secondary)
                        }
                        Spacer()
                        if m.purgando {
                            ProgressView().controlSize(.small)
                        } else {
                            Button("Purgar…") { confirmarPurga = true }.tint(.red).buttonStyle(.borderedProminent)
                        }
                    }
                    .padding(12)
                    .background(Color.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
                }
                ForEach(m.operaciones) { op in fila(op) }
                Text(m.purgaAutorizada
                     ? "El espacio de la cuarentena se libera al purgarla. Solo se puede purgar lo que lleve \(m.dias) días o más, y siempre lo decides tú."
                     : "El espacio de la cuarentena se libera al purgarla. La purga real no está autorizada: solo se puede restaurar.")
                    .font(.caption).foregroundStyle(.tertiary)
            }
            .padding(24)
            .frame(maxWidth: 900, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .onAppear { m.cargar() }
        .confirmationDialog("¿Purgar definitivamente lo que lleva \(m.dias) días o más en la cuarentena?", isPresented: $confirmarPurga) {
            Button("Purgar (\(Formato.bytes(m.caducadas.reduce(Int64(0)) { $0 + $1.bytes })))", role: .destructive) {
                Task { await m.purgar() }
            }
            Button("Cancelar", role: .cancel) {}
        } message: {
            Text("Se borrarán de verdad y no se podrán restaurar. macOS te pedirá permiso para usar la clave de mac-cleaner del Llavero: pulsa «Permitir».")
        }
        .confirmationDialog("¿Restaurar la operación \(confirmar?.id ?? "")?", isPresented: Binding(
            get: { confirmar != nil }, set: { if !$0 { confirmar = nil } }
        )) {
            Button("Restaurar") { if let op = confirmar { Task { await m.restaurar(op) } } }
            Button("Cancelar", role: .cancel) {}
        } message: {
            Text("Los ficheros vuelven a su ruta original; nunca se sobrescribe nada. macOS te pedirá permiso para usar la clave de mac-cleaner del Llavero: pulsa «Permitir» (no «Permitir siempre»).")
        }
    }

    private func fila(_ op: OperacionCuarentena) -> some View {
        HStack(spacing: 14) {
            Image(systemName: op.pendientes > 0 ? "shippingbox.fill" : "checkmark.circle")
                .font(.title2)
                .foregroundStyle(op.pendientes > 0 ? Color.accentColor : Color.secondary)
                .frame(width: 34)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(op.fecha.map { Formato.fechaHora.string(from: $0) } ?? op.id).font(.headline)
                    ForEach(op.reglas, id: \.self) { Etiqueta(texto: Categoria.nombre($0), color: .blue) }
                }
                Text(op.pendientes > 0
                     ? "\(Formato.numero(op.pendientes)) ficheros en cuarentena · autorización \(op.autorizacion)"
                     : "Restaurada entera (\(Formato.numero(op.restaurados)) ficheros) · autorización \(op.autorizacion)")
                    .font(.callout).foregroundStyle(.secondary)
                if op.pendientes > 0, let p = op.purgableDesde(dias: m.dias) {
                    Text("Se podrá purgar a partir del \(Formato.fecha.string(from: p))").font(.caption).foregroundStyle(.tertiary)
                }
            }
            Spacer()
            Text(Formato.bytes(op.bytes)).monospacedDigit()
            if m.restaurando == op.id {
                ProgressView().controlSize(.small).frame(width: 90)
            } else {
                Button("Restaurar…") { confirmar = op }
                    .disabled(op.pendientes == 0 || m.restaurando != nil)
                    .frame(width: 90)
            }
        }
        .padding(12)
        .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 12))
    }
}
