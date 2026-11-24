import SwiftUI

/// F5B: limpieza real desde la app. Paso 1 vista previa (solo lectura), paso 2 confirmación del usuario y
/// limpieza (plan firmado + apply en un solo proceso del motor). Todo va a la cuarentena; nada se borra.
@MainActor
final class LimpiezaModelo: ObservableObject {
    enum Estado {
        case preparando
        case lista(VistaPrevia)
        case limpiando(Int64)
        case hecha(ResultadoLimpieza)
        case error(String)
    }

    @Published var estado: Estado = .preparando
    @Published var elegidas: Set<String> = []

    func preparar() async {
        estado = .preparando
        do {
            let vp = try await Motor.vistaPrevia()
            elegidas = Set(vp.reglas.filter { $0.value.ficheros > 0 }.keys)
            estado = .lista(vp)
        } catch {
            estado = .error(error.localizedDescription)
        }
    }

    func bytesElegidos(_ vp: VistaPrevia) -> Int64 {
        vp.reglas.filter { elegidas.contains($0.key) }.reduce(0) { $0 + $1.value.bytes }
    }

    /// Tope que se pasa al motor: lo que el usuario ve más un margen pequeño (las cachés cambian entre la vista
    /// previa y la limpieza), nunca por encima del máximo autorizado.
    func tope(_ vp: VistaPrevia) -> Int64 {
        let b = bytesElegidos(vp)
        return min(vp.max_bytes, b + max(b / 100, 10_000_000))
    }

    func limpiar(_ vp: VistaPrevia) async {
        let t = tope(vp)
        estado = .limpiando(bytesElegidos(vp))
        do {
            estado = .hecha(try await Motor.limpiar(hastaBytes: t, reglas: elegidas.sorted()))
        } catch {
            estado = .error(error.localizedDescription)
        }
    }
}

struct LimpiezaSheet: View {
    @StateObject private var m = LimpiezaModelo()
    @Environment(\.dismiss) private var cerrar
    var alTerminar: () -> Void = {}

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Image(systemName: "sparkles").font(.title2).foregroundStyle(.tint)
                Text("Limpiar").font(.title2.bold())
                Spacer()
            }
            contenido
        }
        .padding(24)
        .frame(width: 600)
        .frame(minHeight: 360)
        .task { await m.preparar() }
    }

    @ViewBuilder private var contenido: some View {
        switch m.estado {
        case .preparando:
            espera("Revisando qué se puede limpiar…", "Escaneo y comprobación en sombra (no se mueve nada). Unos 20 segundos.")
            Spacer()
            HStack { Spacer(); Button("Cancelar") { cerrar() } }
        case let .lista(vp):
            lista(vp)
        case let .limpiando(b):
            espera("Moviendo \(Formato.bytes(b)) a la cuarentena…",
                   "macOS te pedirá permiso para usar la clave de mac-cleaner del Llavero: pulsa «Permitir» (no «Permitir siempre»).")
            Spacer()
        case let .hecha(r):
            hecha(r)
        case let .error(e):
            Label(e, systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .textSelection(.enabled)
            Text("No se ha movido nada que no esté registrado. Puedes volver a intentarlo.").font(.callout).foregroundStyle(.secondary)
            Spacer()
            HStack {
                Spacer()
                Button("Cerrar") { cerrar() }
                Button("Reintentar") { Task { await m.preparar() } }.buttonStyle(.borderedProminent)
            }
        }
    }

    private func espera(_ titulo: String, _ detalle: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            ProgressView().controlSize(.small)
            VStack(alignment: .leading, spacing: 4) {
                Text(titulo)
                Text(detalle).font(.callout).foregroundStyle(.secondary)
            }
        }
        .padding(.top, 8)
    }

    @ViewBuilder private func lista(_ vp: VistaPrevia) -> some View {
        if let b = vp.bloqueada {
            Label(b, systemImage: "lock.fill").foregroundStyle(.orange)
        }
        let orden = vp.reglas.sorted { $0.value.bytes > $1.value.bytes }
        if orden.isEmpty && vp.bloqueada == nil {
            Label("No hay nada que limpiar ahora mismo.", systemImage: "checkmark.circle").foregroundStyle(.green)
        }
        ScrollView {
            VStack(spacing: 8) {
                ForEach(orden, id: \.key) { regla, c in
                    FilaElegible(regla: regla, c: c, elegida: Binding(
                        get: { m.elegidas.contains(regla) },
                        set: { if $0 { m.elegidas.insert(regla) } else { m.elegidas.remove(regla) } }))
                }
                ForEach(vp.omitidas.sorted { $0.key < $1.key }, id: \.key) { regla, motivo in
                    HStack(spacing: 10) {
                        Image(systemName: "pause.circle").foregroundStyle(.secondary).frame(width: 20)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("\(Categoria.nombre(regla)): se omite esta vez").font(.callout)
                            Text(motivo).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                        }
                        Spacer()
                    }
                    .padding(10)
                }
            }
        }
        .frame(maxHeight: 300)
        let total = m.bytesElegidos(vp)
        Text("Todo va a la cuarentena \(vp.dias_cuarentena) días y se puede restaurar. El espacio se libera al purgarla, a partir del \(Formato.fecha.string(from: Date().addingTimeInterval(Double(vp.dias_cuarentena) * 86400))).")
            .font(.caption).foregroundStyle(.secondary)
        if total > vp.max_bytes {
            Text("Lo elegido supera el tope autorizado por limpieza (\(Formato.bytes(vp.max_bytes))): desmarca alguna categoría.")
                .font(.caption).foregroundStyle(.red)
        }
        HStack {
            Spacer()
            Button("Cancelar") { cerrar() }
            Button {
                Task { await m.limpiar(vp) }
            } label: {
                Text("Mover a la cuarentena (\(Formato.bytes(total)))")
            }
            .buttonStyle(.borderedProminent)
            .disabled(vp.bloqueada != nil || m.elegidas.isEmpty || total == 0 || total > vp.max_bytes)
        }
    }

    @ViewBuilder private func hecha(_ r: ResultadoLimpieza) -> some View {
        let ok = r.abortado == nil && r.errores == 0
        Label(ok ? "Hecho: \(Formato.numero(r.movidos)) ficheros (\(Formato.bytes(r.bytes_movidos))) en la cuarentena."
                 : "Limpieza incompleta: \(Formato.numero(r.movidos)) ficheros movidos.",
              systemImage: ok ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
            .foregroundStyle(ok ? .green : .orange)
            .font(.headline)
        if r.omitidos > 0 {
            Text("\(Formato.numero(r.omitidos)) se omitieron porque cambiaron o se abrieron justo antes de moverlos (es normal).")
                .font(.callout).foregroundStyle(.secondary)
        }
        if let a = r.abortado {
            Text("Se detuvo: \(a). Lo ya movido está registrado y se puede restaurar.").font(.callout).foregroundStyle(.orange)
        }
        Text("Operación \(r.op). La tienes en la sección Cuarentena.").font(.caption).foregroundStyle(.secondary)
        Spacer()
        HStack {
            Spacer()
            Button("Cerrar") {
                alTerminar()
                cerrar()
            }
            .buttonStyle(.borderedProminent)
        }
    }
}

private struct FilaElegible: View {
    let regla: String
    let c: VistaPrevia.Seleccion
    @Binding var elegida: Bool
    @State private var abierta = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 10) {
                Toggle("", isOn: $elegida).labelsHidden()
                Image(systemName: Categoria.simbolo(regla)).foregroundStyle(.tint).frame(width: 20)
                VStack(alignment: .leading, spacing: 1) {
                    Text(Categoria.nombre(regla)).font(.headline)
                    Text("\(Formato.numero(c.ficheros)) ficheros").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Text(Formato.bytes(c.bytes)).monospacedDigit()
                Button {
                    withAnimation(.snappy) { abierta.toggle() }
                } label: {
                    Image(systemName: "chevron.right").rotationEffect(.degrees(abierta ? 90 : 0))
                }
                .buttonStyle(.borderless)
            }
            if abierta {
                ForEach(c.grupos) { g in
                    HStack {
                        Text(g.grupo).lineLimit(1).truncationMode(.middle)
                        Spacer()
                        Text(Formato.bytes(g.bytes)).monospacedDigit().foregroundStyle(.secondary)
                    }
                    .font(.caption)
                    .padding(.leading, 64)
                }
            }
        }
        .padding(10)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 10))
    }
}
