#!/usr/bin/env python3
"""
App Móvil: Conversor de Chat de Instagram a PDF
Interfaz gráfica construida con Kivy — ejecutable en Android, iOS, Windows, Linux y macOS.

Requisitos:
    pip install kivy beautifulsoup4 fpdf2

Para compilar en Android:
    Usa Buildozer: https://buildozer.readthedocs.io
"""

import os
import sys
import threading

# Configuración de Kivy antes de importar cualquier módulo de Kivy
os.environ.setdefault("KIVY_NO_ENV_CONFIG", "1")

try:
    import kivy
    kivy.require("2.0.0")

    from kivy.app import App
    from kivy.uix.boxlayout import BoxLayout
    from kivy.uix.floatlayout import FloatLayout
    from kivy.uix.scrollview import ScrollView
    from kivy.uix.label import Label
    from kivy.uix.button import Button
    from kivy.uix.togglebutton import ToggleButton
    from kivy.uix.textinput import TextInput
    from kivy.uix.filechooser import FileChooserListView
    from kivy.uix.popup import Popup
    from kivy.uix.progressbar import ProgressBar
    from kivy.graphics import Color, Rectangle, RoundedRectangle
    from kivy.clock import Clock
    from kivy.metrics import dp
    from kivy.core.window import Window
    KIVY_AVAILABLE = True
except ImportError:
    KIVY_AVAILABLE = False

# Importar el módulo de conversión
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from html_to_pdf import convert_html_to_pdf


# ─────────────────────────────────────────────
#  Constantes de diseño
# ─────────────────────────────────────────────
BG_COLOR      = (0.07, 0.07, 0.07, 1)
PRIMARY_COLOR = (0.0,  0.58, 0.96, 1)
SURFACE_COLOR = (0.14, 0.14, 0.14, 1)
TEXT_COLOR    = (1.0,  1.0,  1.0,  1)
META_COLOR    = (0.67, 0.67, 0.67, 1)
SUCCESS_COLOR = (0.13, 0.74, 0.34, 1)
ERROR_COLOR   = (0.9,  0.2,  0.2,  1)


if KIVY_AVAILABLE:

    class StyledButton(Button):
        """Botón con estilo redondeado y color primario."""

        def __init__(self, primary=True, **kwargs):
            super().__init__(**kwargs)
            self.background_color = (0, 0, 0, 0)
            self.color = TEXT_COLOR
            self.font_size = dp(15)
            self.bold = True
            self._primary = primary
            self.bind(pos=self._update_canvas, size=self._update_canvas)

        def _update_canvas(self, *_):
            self.canvas.before.clear()
            fill = PRIMARY_COLOR if self._primary else SURFACE_COLOR
            with self.canvas.before:
                Color(*fill)
                RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(10)])

    class FileItem(BoxLayout):
        """Widget para mostrar un archivo seleccionado con botón de eliminar."""

        def __init__(self, filepath: str, on_remove, **kwargs):
            super().__init__(orientation="horizontal", size_hint_y=None, height=dp(40), **kwargs)
            self.filepath = filepath
            self.padding = [dp(8), dp(4)]
            self.spacing = dp(6)

            with self.canvas.before:
                Color(*SURFACE_COLOR)
                self._bg = RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(8)])
            self.bind(pos=self._upd, size=self._upd)

            name = os.path.basename(filepath)
            lbl = Label(text=name, color=TEXT_COLOR, font_size=dp(12),
                        halign="left", valign="middle", text_size=(None, None))
            lbl.bind(size=lambda inst, v: setattr(inst, "text_size", (v[0], None)))
            self.add_widget(lbl)

            btn = Button(text="✕", size_hint=(None, None),
                         width=dp(32), height=dp(32),
                         background_color=(0, 0, 0, 0),
                         color=ERROR_COLOR, font_size=dp(16), bold=True)
            btn.bind(on_release=lambda _: on_remove(self))
            self.add_widget(btn)

        def _upd(self, *_):
            self._bg.pos = self.pos
            self._bg.size = self.size

    class HTMLtoPDFApp(App):
        """App principal — Conversor de Chat de Instagram a PDF."""

        def build(self):
            Window.clearcolor = BG_COLOR
            self.title = "Chat Instagram → PDF"
            self.selected_files = []

            root = BoxLayout(orientation="vertical", padding=dp(16), spacing=dp(12))

            # ── Encabezado ──────────────────────────────────────────────
            header = BoxLayout(orientation="vertical", size_hint_y=None, height=dp(70))
            title_lbl = Label(
                text="💬  Chat → PDF",
                font_size=dp(24), bold=True, color=PRIMARY_COLOR,
                halign="center", size_hint_y=None, height=dp(36),
            )
            subtitle_lbl = Label(
                text="Convierte chats de Instagram a PDF",
                font_size=dp(12), color=META_COLOR,
                halign="center", size_hint_y=None, height=dp(20),
            )
            header.add_widget(title_lbl)
            header.add_widget(subtitle_lbl)
            root.add_widget(header)

            # ── Botón seleccionar archivos ───────────────────────────────
            btn_select = StyledButton(text="📂  Seleccionar archivos HTML", size_hint_y=None, height=dp(48))
            btn_select.bind(on_release=self.open_file_chooser)
            root.add_widget(btn_select)

            # ── Lista de archivos seleccionados ─────────────────────────
            list_label = Label(
                text="Archivos seleccionados:",
                color=META_COLOR, font_size=dp(11),
                halign="left", size_hint_y=None, height=dp(20),
            )
            list_label.bind(size=lambda i, v: setattr(i, "text_size", (v[0], None)))
            root.add_widget(list_label)

            scroll = ScrollView(size_hint=(1, 1))
            self.file_list = BoxLayout(
                orientation="vertical", spacing=dp(4),
                size_hint_y=None, padding=[0, 4],
            )
            self.file_list.bind(minimum_height=self.file_list.setter("height"))
            scroll.add_widget(self.file_list)
            root.add_widget(scroll)

            # ── Mensaje de estado / vacío ────────────────────────────────
            self.empty_label = Label(
                text="(ningún archivo seleccionado)",
                color=META_COLOR, font_size=dp(12),
                halign="center", size_hint_y=None, height=dp(30),
            )
            self.file_list.add_widget(self.empty_label)

            # ── Modo de salida ───────────────────────────────────────────
            mode_label = Label(
                text="Modo de salida:",
                color=META_COLOR, font_size=dp(11),
                halign="left", size_hint_y=None, height=dp(20),
            )
            mode_label.bind(size=lambda i, v: setattr(i, "text_size", (v[0], None)))
            root.add_widget(mode_label)

            mode_row = BoxLayout(orientation="horizontal", size_hint_y=None, height=dp(42), spacing=dp(8))
            self.btn_combined = ToggleButton(
                text="📄 Un solo PDF", group="mode", state="down",
                background_color=(0, 0, 0, 0), color=TEXT_COLOR,
                font_size=dp(13), bold=True,
            )
            self.btn_separate = ToggleButton(
                text="📑 PDFs separados", group="mode",
                background_color=(0, 0, 0, 0), color=TEXT_COLOR,
                font_size=dp(13), bold=True,
            )
            for btn in (self.btn_combined, self.btn_separate):
                btn.bind(pos=self._update_toggle_bg, size=self._update_toggle_bg,
                         state=self._update_toggle_bg)
            mode_row.add_widget(self.btn_combined)
            mode_row.add_widget(self.btn_separate)
            root.add_widget(mode_row)

            # ── Nombre del PDF de salida (modo combinado) ────────────────
            self.output_row = BoxLayout(orientation="vertical", size_hint_y=None, height=dp(60), spacing=dp(4))
            out_lbl = Label(
                text="Nombre del PDF de salida:",
                color=META_COLOR, font_size=dp(11),
                halign="left", size_hint_y=None, height=dp(20),
            )
            out_lbl.bind(size=lambda i, v: setattr(i, "text_size", (v[0], None)))
            self.output_name = TextInput(
                text="chat_exportado.pdf",
                hint_text="Nombre del archivo de salida",
                size_hint_y=None, height=dp(36),
                background_color=SURFACE_COLOR,
                foreground_color=TEXT_COLOR,
                cursor_color=PRIMARY_COLOR,
                font_size=dp(13),
                multiline=False,
            )
            self.output_row.add_widget(out_lbl)
            self.output_row.add_widget(self.output_name)
            self.btn_combined.bind(state=self._toggle_output_row)
            root.add_widget(self.output_row)

            # ── Barra de progreso ────────────────────────────────────────
            self.progress = ProgressBar(max=100, value=0, size_hint_y=None, height=dp(6))
            root.add_widget(self.progress)

            # ── Mensaje de resultado ─────────────────────────────────────
            self.status_label = Label(
                text="",
                font_size=dp(12), color=META_COLOR,
                halign="center", size_hint_y=None, height=dp(30),
            )
            self.status_label.bind(size=lambda i, v: setattr(i, "text_size", (v[0], None)))
            root.add_widget(self.status_label)

            # ── Botón Convertir ──────────────────────────────────────────
            btn_convert = StyledButton(text="🚀  Convertir a PDF", size_hint_y=None, height=dp(52))
            btn_convert.bind(on_release=self.start_conversion)
            root.add_widget(btn_convert)

            return root

        # ── Helpers de estilo ────────────────────────────────────────────
        def _update_toggle_bg(self, instance, *_):
            instance.canvas.before.clear()
            color = PRIMARY_COLOR if instance.state == "down" else SURFACE_COLOR
            with instance.canvas.before:
                Color(*color)
                RoundedRectangle(pos=instance.pos, size=instance.size, radius=[dp(10)])

        def _toggle_output_row(self, instance, value):
            self.output_row.opacity = 1 if value == "down" else 0
            self.output_row.disabled = value != "down"

        # ── Selector de archivos ─────────────────────────────────────────
        def open_file_chooser(self, *_):
            content = BoxLayout(orientation="vertical", spacing=dp(8), padding=dp(12))

            fc = FileChooserListView(
                filters=["*.html", "*.htm"],
                multiselect=True,
                path=os.path.expanduser("~"),
            )
            content.add_widget(fc)

            btn_row = BoxLayout(size_hint_y=None, height=dp(44), spacing=dp(8))
            btn_cancel = StyledButton(text="Cancelar", primary=False)
            btn_ok = StyledButton(text="Añadir archivos")

            popup = Popup(
                title="Seleccionar archivos HTML",
                content=content,
                size_hint=(0.95, 0.85),
            )

            def add_files(_):
                for f in fc.selection:
                    if f not in self.selected_files:
                        self.selected_files.append(f)
                self._refresh_file_list()
                popup.dismiss()

            btn_cancel.bind(on_release=popup.dismiss)
            btn_ok.bind(on_release=add_files)
            btn_row.add_widget(btn_cancel)
            btn_row.add_widget(btn_ok)
            content.add_widget(btn_row)
            popup.open()

        # ── Actualizar lista visual ──────────────────────────────────────
        def _refresh_file_list(self):
            self.file_list.clear_widgets()
            if not self.selected_files:
                self.file_list.add_widget(self.empty_label)
                return
            for fp in self.selected_files:
                item = FileItem(fp, on_remove=self._remove_file)
                self.file_list.add_widget(item)

        def _remove_file(self, item):
            if item.filepath in self.selected_files:
                self.selected_files.remove(item.filepath)
            self._refresh_file_list()

        # ── Conversión ───────────────────────────────────────────────────
        def start_conversion(self, *_):
            if not self.selected_files:
                self._set_status("⚠ Selecciona al menos un archivo HTML.", ERROR_COLOR)
                return

            self.progress.value = 10
            self._set_status("Convirtiendo…", META_COLOR)

            separados = self.btn_separate.state == "down"
            output_name = self.output_name.text.strip() or "chat_exportado.pdf"
            if not output_name.lower().endswith(".pdf"):
                output_name += ".pdf"

            # Directorio de salida = junto al primer archivo seleccionado
            output_dir = os.path.dirname(os.path.abspath(self.selected_files[0]))
            output_path = os.path.join(output_dir, output_name) if not separados else None

            def do_convert():
                results = convert_html_to_pdf(
                    html_files=list(self.selected_files),
                    output=output_path,
                    separados=separados,
                    output_dir=output_dir,
                )
                Clock.schedule_once(lambda dt: self._on_done(results))

            t = threading.Thread(target=do_convert, daemon=True)
            t.start()

        def _on_done(self, results):
            self.progress.value = 100
            if results:
                names = "\n".join(os.path.basename(r) for r in results)
                self._set_status(f"✓ {len(results)} PDF(s) generado(s):\n{names}", SUCCESS_COLOR)
            else:
                self._set_status("✗ Error al generar el PDF. Revisa los archivos.", ERROR_COLOR)
            Clock.schedule_once(lambda dt: setattr(self.progress, "value", 0), 3)

        def _set_status(self, msg: str, color=None):
            self.status_label.text = msg
            if color:
                self.status_label.color = color


def run_app():
    """Punto de entrada para la app móvil."""
    if not KIVY_AVAILABLE:
        print("[ERROR] Kivy no está instalado. Ejecuta: pip install kivy")
        print("Usa html_to_pdf.py directamente para la versión CLI.")
        sys.exit(1)
    HTMLtoPDFApp().run()


if __name__ == "__main__":
    run_app()
