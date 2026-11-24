import AppKit
import SwiftUI

@MainActor
final class EscaneoRapidoModelo: ObservableObject {
    @Published var escaneo: Escaneo?
    @Published var ruta: URL?
    @Published var autorizacion: Autorizacion?
    @Published var escaneando = false
    @Published var error: String?
    @Published var inicio: Date?

    func cargarInicial() async {
        if escaneo == nil, let u = Motor.ultimoEscaneo() { cargar(u) }
        await refrescarAutorizacion()
    }

    func refrescarAutorizacion() async {
        autorizacion = try? await Motor.autorizacion()
    }

    func escanear() async {
        guard !escaneando else { return }
        escaneando = true
        inicio = Date()
        error = nil
        defer { escaneando = false }
        do {
            let u = try await Motor.escanear()
            cargar(u)
            await refrescarAutorizacion()
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func cargar(_ u: URL) {
        do {
            let d = try Data(contentsOf: u)
            escaneo = try JSONDecoder().decode(Escaneo.self, from: d)
            ruta = u
        } catch {
            self.error = "No se puede leer el escaneo \(u.lastPathComponent): \(error.localizedDescription)"
        }
    }

    var hayLimpiable: Bool {
        guard let a = autorizacion, let e = escaneo else { return false }
        return e.escaneo.reglas.contains { a.autoriza($0.id) && ($0.totales.recuperable_conservador ?? 0) > 0 }
    }
}

struct EscaneoRapidoView: View {
    @StateObject private var m = EscaneoRapidoModelo()
    @State private var limpiando = false

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    cabecera
                    if let d = m.escaneo?.disco { tarjetaDisco(d) }
                    if m.escaneando { progreso }
                    if let e = m.error { aviso(e) }
                    if let e = m.escaneo { resumen(e); categorias(e) } else if !m.escaneando { vacio }
                }
                .padding(24)
                .frame(maxWidth: 900, alignment: .leading)
                .frame(maxWidth: .infinity)
            }
            Divider()
            barraInferior
        }
        .task { await m.cargarInicial() }
        .onReceive(NotificationCenter.default.publisher(for: .abrirLimpiezaParaCaptura)) { _ in limpiando = true }
        .sheet(isPresented: $limpiando) {
            LimpiezaSheet { Task { await m.escanear() } }
        }
    }

    private var cabecera: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Escaneo rápido").font(.largeTitle.bold())
                Text("Cachés, registros y temporales que se pueden regenerar. El escaneo solo lee: no mueve ni borra nada.")
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                Task { await m.escanear() }
            } label: {
                Label(m.escaneo == nil ? "Escanear" : "Volver a escanear", systemImage: "sparkle.magnifyingglass")
                    .padding(.horizontal, 8)
            }
            .controlSize(.large)
            .buttonStyle(.borderedProminent)
            .disabled(m.escaneando)
        }
    }

    private func tarjetaDisco(_ d: Escaneo.Disco) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                BarraSegmentos(segmentos: [.init(valor: Double(d.usado), color: .accentColor)], total: Double(d.total), alto: 14)
                HStack(spacing: 18) {
                    Leyenda(color: .accentColor, titulo: "Usado", valor: Formato.bytes(d.usado))
                    Leyenda(color: .secondary.opacity(0.3), titulo: "Libre", valor: Formato.bytes(d.libre))
                    Spacer()
                    Text("Disco de \(Formato.bytes(d.total))").foregroundStyle(.secondary).font(.callout)
                }
            }
            .padding(6)
        } label: {
            Label("Disco de arranque", systemImage: "internaldrive")
        }
    }

    private var progreso: some View {
        HStack(spacing: 12) {
            ProgressView().controlSize(.small)
            VStack(alignment: .leading) {
                Text("Escaneando… suele tardar unos 15 segundos.")
                Text("Prioridad baja: puedes seguir trabajando.").font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 10))
    }

    private func aviso(_ texto: String) -> some View {
        Label(texto, systemImage: "exclamationmark.triangle.fill")
            .foregroundStyle(.orange)
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.orange.opacity(0.1), in: RoundedRectangle(cornerRadius: 10))
    }

    private var vacio: some View {
        VStack(spacing: 12) {
            Image(systemName: "sparkles").font(.system(size: 44)).foregroundStyle(.tint)
            Text("Todavía no hay ningún escaneo").font(.title3)
            Text("Pulsa «Escanear» para ver cuánto ocupan las cachés y qué se podría recuperar.").foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 60)
    }

    private func resumen(_ e: Escaneo) -> some View {
        HStack(spacing: 14) {
            cifra("Recuperable (conservador)", Formato.bytes(e.totalRecuperable), "leaf", .green,
                  "Grupos enteros sin uso reciente, sin ficheros abiertos y sin riesgo alto.")
            cifra("Candidatos", Formato.bytes(e.totalCandidatos), "line.3.horizontal.decrease.circle", .blue,
                  "Ficheros más antiguos que el umbral de su categoría. Es una cota superior.")
            cifra("Ocupado en total", Formato.bytes(e.totalFisico), "externaldrive", .secondary,
                  "Todo lo que ocupan estas categorías, se pueda limpiar o no.")
        }
    }

    private func cifra(_ titulo: String, _ valor: String, _ simbolo: String, _ color: Color, _ ayuda: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(titulo, systemImage: simbolo).font(.callout).foregroundStyle(color)
            Text(valor).font(.title.bold()).monospacedDigit()
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 12))
        .help(ayuda)
    }

    private func categorias(_ e: Escaneo) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Categorías").font(.title2.bold())
                Spacer()
                if let f = e.fechaGenerado {
                    Text("Escaneado \(Formato.relativa(f))").foregroundStyle(.secondary).font(.callout)
                }
            }
            ForEach(e.escaneo.reglas.sorted { ($0.totales.fisico ?? 0) > ($1.totales.fisico ?? 0) }) { r in
                FilaCategoria(regla: r, autorizada: m.autorizacion?.autoriza(r.id) ?? false)
            }
        }
    }

    private var barraInferior: some View {
        HStack(spacing: 12) {
            if let a = m.autorizacion {
                Image(systemName: a.vigente ? "checkmark.shield" : "lock.shield")
                    .foregroundStyle(a.vigente ? .green : .secondary)
                VStack(alignment: .leading, spacing: 2) {
                    Text(a.vigente ? "Autorización \(a.id) vigente" : "Limpieza real bloqueada")
                        .font(.callout.weight(.semibold))
                    Text(a.vigente
                         ? "Solo \(a.reglas.map(Categoria.nombre).joined(separator: ", ")); todo a la cuarentena \(a.dias_cuarentena) días."
                         : "La autorización \(a.id) no está vigente.")
                        .font(.caption).foregroundStyle(.secondary)
                        .lineLimit(2)
                }
            } else {
                Text("Consultando la autorización del motor…").font(.callout).foregroundStyle(.secondary)
            }
            Spacer()
            if let u = m.ruta {
                Button("Ver informes") { NSWorkspace.shared.activateFileViewerSelecting([u]) }
            }
            Button {
                limpiando = true
            } label: {
                Label("Limpiar…", systemImage: "sparkles")
            }
            .buttonStyle(.borderedProminent)
            .disabled(!(m.autorizacion?.vigente ?? false) || m.escaneando)
            .help("Te enseña qué se movería a la cuarentena y te pide confirmación.")
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 12)
        .background(.bar)
    }
}

struct FilaCategoria: View {
    let regla: Escaneo.Regla
    let autorizada: Bool
    @State private var abierta = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(.snappy) { abierta.toggle() }
            } label: {
                HStack(spacing: 12) {
                    Image(systemName: Categoria.simbolo(regla.id))
                        .font(.title3)
                        .frame(width: 34, height: 34)
                        .background(Color.accentColor.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
                        .foregroundStyle(.tint)
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Text(Categoria.nombre(regla.id)).font(.headline)
                            if autorizada {
                                Etiqueta(texto: "Autorizada", color: .green)
                            }
                        }
                        Text(regla.descripcion ?? "").font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    }
                    Spacer()
                    VStack(alignment: .trailing, spacing: 2) {
                        Text(Formato.bytes(regla.totales.fisico ?? 0)).font(.headline).monospacedDigit()
                        let rec = regla.totales.recuperable_conservador ?? 0
                        Text(rec > 0 ? "\(Formato.bytes(rec)) recuperable" : "nada recuperable ahora")
                            .font(.caption).foregroundStyle(rec > 0 ? .green : .secondary)
                    }
                    Image(systemName: "chevron.right")
                        .rotationEffect(.degrees(abierta ? 90 : 0))
                        .foregroundStyle(.tertiary)
                }
                .contentShape(Rectangle())
                .padding(12)
            }
            .buttonStyle(.plain)

            if abierta {
                Divider().padding(.leading, 58)
                VStack(alignment: .leading, spacing: 6) {
                    if let d = regla.edad_minima_dias {
                        Text(d > 0 ? "Umbral: \(Int(d)) días sin cambios." : "Caché gestionada por su herramienta (sin umbral de antigüedad).")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    ForEach((regla.grupos ?? []).sorted { ($0.fisico ?? 0) > ($1.fisico ?? 0) }.prefix(12)) { g in
                        FilaGrupo(grupo: g)
                    }
                    if (regla.n_grupos ?? 0) > 12 {
                        Text("… y \((regla.n_grupos ?? 0) - 12) grupos más en el informe.").font(.caption).foregroundStyle(.secondary)
                    }
                }
                .padding(.leading, 58)
                .padding([.trailing, .bottom], 12)
                .padding(.top, 8)
            }
        }
        .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 12))
    }
}

struct FilaGrupo: View {
    let grupo: Escaneo.Grupo

    var body: some View {
        HStack(spacing: 8) {
            Text(grupo.nombre).lineLimit(1).truncationMode(.middle)
            if let r = grupo.riesgo, r != "bajo" {
                Etiqueta(texto: "riesgo \(r)", color: r == "alto" ? .red : .orange)
                    .help(grupo.motivo_riesgo ?? "")
            }
            Spacer()
            Text(estadoCorto).font(.caption).foregroundStyle(.secondary)
            Text(Formato.bytes(grupo.fisico ?? 0)).monospacedDigit().frame(width: 90, alignment: .trailing)
            if let ruta = grupo.ruta {
                Button {
                    NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: ruta)])
                } label: {
                    Image(systemName: "magnifyingglass.circle")
                }
                .buttonStyle(.borderless)
                .help("Mostrar en el Finder")
            }
        }
        .font(.callout)
    }

    private var estadoCorto: String {
        guard let e = grupo.estado else { return "" }
        if e.hasPrefix("en uso") { return "en uso" }
        if e.hasPrefix("activo") { return "activo" }
        if e.hasPrefix("inactivo") { return "inactivo" }
        if e.hasPrefix("regenerable") { return "regenerable" }
        return e
    }
}
