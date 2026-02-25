#!/usr/bin/env python3
"""
Conversor de HTML a PDF para chats de Instagram
Convierte archivos message_1.html (exportaciones de Instagram) a PDF legibles.
Soporta combinar múltiples archivos HTML en un único PDF o generar PDFs separados.

Uso CLI:
    python html_to_pdf.py archivo1.html archivo2.html --output chat.pdf
    python html_to_pdf.py *.html --separados
    python html_to_pdf.py                          # Modo interactivo
"""

import os
import sys
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Optional

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("Error: Falta beautifulsoup4. Ejecuta: pip install beautifulsoup4")
    sys.exit(1)

try:
    from fpdf import FPDF
except ImportError:
    print("Error: Falta fpdf2. Ejecuta: pip install fpdf2")
    sys.exit(1)


# ─────────────────────────────────────────────
#  Constantes de estilo
# ─────────────────────────────────────────────
COLOR_BG        = (18, 18, 18)    # Fondo oscuro (estilo Instagram DM)
COLOR_MSG_LEFT  = (37, 37, 37)    # Burbuja mensaje recibido
COLOR_MSG_RIGHT = (0, 149, 246)   # Burbuja mensaje enviado (azul Instagram)
COLOR_TEXT      = (255, 255, 255) # Texto principal
COLOR_META      = (170, 170, 170) # Timestamps y metadatos
COLOR_HEADER    = (0, 149, 246)   # Color de encabezado
PAGE_MARGIN     = 10              # Márgenes de página en mm
BUBBLE_PADDING  = 3               # Relleno interior de burbuja


# ─────────────────────────────────────────────
#  Parser de HTML de Instagram
# ─────────────────────────────────────────────
class InstagramHTMLParser:
    """
    Parsea archivos HTML exportados de Instagram (Descarga de datos).
    Compatible con el formato message_1.html.
    """

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.conversation_title = ""
        self.participants: List[str] = []
        self.messages: List[dict] = []

    def parse(self) -> bool:
        """Parsea el archivo HTML y extrae los mensajes. Devuelve True si tuvo éxito."""
        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                content = f.read()
        except UnicodeDecodeError:
            # Segundo intento con latin-1
            try:
                with open(self.filepath, "r", encoding="latin-1") as f:
                    content = f.read()
            except Exception as e:
                print(f"[ERROR] No se pudo leer {self.filepath}: {e}")
                return False
        except Exception as e:
            print(f"[ERROR] No se pudo leer {self.filepath}: {e}")
            return False

        soup = BeautifulSoup(content, "html.parser")

        # Extraer título de la conversación
        title_tag = soup.find("title")
        if title_tag:
            self.conversation_title = title_tag.get_text(strip=True)

        # Intentar extraer participantes y mensajes usando diferentes estrategias
        if not self._parse_instagram_format(soup):
            self._parse_generic_format(soup)

        return len(self.messages) > 0

    def _parse_instagram_format(self, soup: BeautifulSoup) -> bool:
        """
        Intenta parsear el formato estándar de exportación de Instagram.
        Devuelve True si se encontraron mensajes con este método.
        """
        messages_found = []

        main_div = soup.find("div", role="main") or soup.find("body")
        if not main_div:
            return False

        # Extraer título/participantes del encabezado
        header_divs = main_div.find_all("div", class_=lambda c: c and "_a6-h" in c, limit=5)
        for div in header_divs:
            text = div.get_text(" ", strip=True)
            if text and len(text) < 200 and not self.conversation_title:
                self.conversation_title = text

        # Buscar SÓLO los bloques de mensaje de nivel superior (clase "_2ph_").
        # Usar sólo "_2ph_" evita capturar divs anidados y duplicar mensajes.
        message_blocks = main_div.find_all(
            "div",
            class_=lambda c: c and "_2ph_" in c,
        )

        # Fallback: si Instagram cambia las clases, intentar con "_a6-p" de nivel 2
        if not message_blocks:
            message_blocks = main_div.find_all(
                "div",
                class_=lambda c: c and "_a6-p" in c and "_2ph_" not in c,
            )

        seen_keys = set()
        for block in message_blocks:
            # Remitente
            sender_tag = block.find("div", class_=lambda c: c and "_2pi0" in c)
            sender = sender_tag.get_text(strip=True) if sender_tag else ""

            # Timestamp
            time_tag = block.find("div", class_=lambda c: c and (
                "_a6-o" in c or "_3-94" in c or "_a6-t" in c
            ))
            timestamp = time_tag.get_text(strip=True) if time_tag else ""

            # Contenido: todo el texto del bloque sin sender ni timestamp
            full_text = block.get_text(" ", strip=True)
            for remove in [sender, timestamp]:
                if remove:
                    full_text = full_text.replace(remove, "", 1).strip()
            content = full_text.strip()

            key = f"{sender}|{content}|{timestamp}"
            if content and key not in seen_keys:
                seen_keys.add(key)
                messages_found.append({
                    "sender": sender,
                    "content": content,
                    "timestamp": timestamp,
                })
                if sender and sender not in self.participants:
                    self.participants.append(sender)

        if messages_found:
            self.messages = messages_found
            return True

        return False

    def _parse_generic_format(self, soup: BeautifulSoup):
        """
        Parsea el HTML de manera genérica cuando el formato específico de
        Instagram no se puede detectar. Extrae todo el texto estructurado.
        """
        body = soup.find("body") or soup
        seen = set()

        # Recorrer todos los párrafos y divs con contenido
        for tag in body.find_all(["p", "div", "span", "li"]):
            # Solo tags de primer/segundo nivel para evitar duplicados
            if tag.find_parent(["p", "li"]):
                continue

            text = tag.get_text(" ", strip=True)
            if len(text) < 2 or len(text) > 2000:
                continue
            if text in seen:
                continue
            seen.add(text)

            self.messages.append({
                "sender": "",
                "content": text,
                "timestamp": "",
            })

        if not self.conversation_title:
            title = soup.find("title")
            self.conversation_title = title.get_text(strip=True) if title else Path(self.filepath).stem


# ─────────────────────────────────────────────
#  Generador de PDF
# ─────────────────────────────────────────────
class ChatPDFGenerator:
    """
    Genera archivos PDF a partir de mensajes de chat de Instagram.
    Usa fpdf2 con diseño oscuro similar al de la app de Instagram.
    """

    def __init__(self):
        self.pdf = FPDF()
        self.pdf.set_auto_page_break(auto=True, margin=15)
        self.pdf.set_margins(PAGE_MARGIN, PAGE_MARGIN, PAGE_MARGIN)
        self._page_width = 210  # A4 en mm
        self._usable_width = self._page_width - 2 * PAGE_MARGIN

    def _add_cover_page(self, title: str, participants: List[str], file_count: int):
        """Añade una página de portada al PDF."""
        self.pdf.add_page()
        self.pdf.set_fill_color(*COLOR_BG)
        self.pdf.rect(0, 0, self.pdf.w, self.pdf.h, "F")

        # Icono decorativo (ASCII seguro)
        self.pdf.set_font("Helvetica", "B", 36)
        self.pdf.set_text_color(*COLOR_HEADER)
        self.pdf.ln(30)
        self.pdf.cell(0, 20, "[ Chat ]", align="C", new_x="LMARGIN", new_y="NEXT")

        # Título
        self.pdf.set_font("Helvetica", "B", 20)
        self.pdf.set_text_color(*COLOR_TEXT)
        self.pdf.multi_cell(0, 12, title or "Chat de Instagram", align="C")
        self.pdf.ln(8)

        # Participantes
        if participants:
            self.pdf.set_font("Helvetica", "", 12)
            self.pdf.set_text_color(*COLOR_META)
            self.pdf.multi_cell(0, 8, "Participantes: " + ", ".join(participants), align="C")
            self.pdf.ln(4)

        # Info archivos
        if file_count > 1:
            self.pdf.set_font("Helvetica", "I", 10)
            self.pdf.set_text_color(*COLOR_META)
            self.pdf.cell(0, 8, f"({file_count} archivos combinados)", align="C", new_x="LMARGIN", new_y="NEXT")

        # Fecha de generación
        self.pdf.ln(10)
        self.pdf.set_font("Helvetica", "I", 9)
        self.pdf.set_text_color(*COLOR_META)
        now = datetime.now().strftime("%d/%m/%Y %H:%M")
        self.pdf.cell(0, 6, f"Generado el {now}", align="C", new_x="LMARGIN", new_y="NEXT")

    def _add_section_header(self, title: str, filepath: str):
        """Añade un encabezado de sección para separar archivos."""
        self.pdf.ln(4)
        self.pdf.set_fill_color(*COLOR_HEADER)
        self.pdf.set_text_color(*COLOR_TEXT)
        self.pdf.set_font("Helvetica", "B", 10)
        label = f"  >> {self._sanitize_text(title or Path(filepath).stem)}  "
        self.pdf.cell(0, 8, label, fill=True, new_x="LMARGIN", new_y="NEXT")
        self.pdf.ln(2)

    def _sanitize_text(self, text: str) -> str:
        """Elimina o reemplaza caracteres no soportados por fpdf2 Latin-1."""
        replacements = {
            "\u2019": "'", "\u2018": "'", "\u201c": '"', "\u201d": '"',
            "\u2013": "-", "\u2014": "--", "\u2026": "...", "\u00a0": " ",
            "\u2764": "<3", "\u2665": "<3", "\u2714": "✓", "\u2716": "x",
        }
        for orig, repl in replacements.items():
            text = text.replace(orig, repl)
        # Eliminar caracteres fuera del rango Latin-1
        return text.encode("latin-1", errors="replace").decode("latin-1")

    def _draw_message_bubble(self, sender: str, content: str, timestamp: str, is_right: bool):
        """
        Dibuja una burbuja de mensaje con fondo de color.
        is_right=True → mensaje enviado (azul, derecha).
        is_right=False → mensaje recibido (gris, izquierda).
        """
        bubble_color = COLOR_MSG_RIGHT if is_right else COLOR_MSG_LEFT
        bubble_w = self._usable_width * 0.72  # 72% del ancho útil

        # Calcular altura del texto de contenido
        self.pdf.set_font("Helvetica", "", 8)
        content_safe = self._sanitize_text(content)

        # Líneas de texto para el contenido
        n_lines = self.pdf.get_string_width(content_safe) / (bubble_w - 2 * BUBBLE_PADDING) + 1
        n_lines = max(1, int(n_lines) + 1)
        content_h = n_lines * 5

        bubble_h = BUBBLE_PADDING + (8 if sender else 0) + content_h + (6 if timestamp else 0) + BUBBLE_PADDING
        bubble_h = max(bubble_h, 12)

        # Posición horizontal de la burbuja
        x_start = PAGE_MARGIN
        if is_right:
            x_start = self.pdf.w - PAGE_MARGIN - bubble_w

        # Verificar si hay espacio en la página actual
        if self.pdf.get_y() + bubble_h + 4 > self.pdf.h - 15:
            self.pdf.add_page()
            self._set_dark_background()

        y_bubble = self.pdf.get_y()

        # Dibujar rectángulo de fondo (burbuja)
        self.pdf.set_fill_color(*bubble_color)
        self.pdf.set_draw_color(*bubble_color)
        self.pdf.rect(x_start, y_bubble, bubble_w, bubble_h, "F")

        # Nombre del remitente
        y_cursor = y_bubble + BUBBLE_PADDING
        if sender:
            sender_safe = self._sanitize_text(sender)
            self.pdf.set_font("Helvetica", "B", 7)
            self.pdf.set_text_color(200, 230, 255) if is_right else self.pdf.set_text_color(*COLOR_META)
            self.pdf.set_xy(x_start + BUBBLE_PADDING, y_cursor)
            self.pdf.cell(bubble_w - 2 * BUBBLE_PADDING, 5, sender_safe, new_x="LMARGIN", new_y="NEXT")
            y_cursor += 6

        # Contenido del mensaje
        self.pdf.set_font("Helvetica", "", 8)
        self.pdf.set_text_color(*COLOR_TEXT)
        self.pdf.set_xy(x_start + BUBBLE_PADDING, y_cursor)
        self.pdf.multi_cell(
            bubble_w - 2 * BUBBLE_PADDING,
            5,
            content_safe,
            new_x="LMARGIN",
            new_y="NEXT",
        )
        y_cursor = self.pdf.get_y()

        # Timestamp
        if timestamp:
            ts_safe = self._sanitize_text(timestamp)
            self.pdf.set_font("Helvetica", "I", 6)
            self.pdf.set_text_color(*COLOR_META)
            self.pdf.set_xy(x_start + BUBBLE_PADDING, y_cursor)
            self.pdf.cell(bubble_w - 2 * BUBBLE_PADDING, 4, ts_safe,
                          align="R" if is_right else "L",
                          new_x="LMARGIN", new_y="NEXT")

        self.pdf.ln(2)

    def _set_dark_background(self):
        """Pinta el fondo de la página actual con el color oscuro."""
        self.pdf.set_fill_color(*COLOR_BG)
        self.pdf.rect(0, 0, self.pdf.w, self.pdf.h, "F")
        self.pdf.set_y(PAGE_MARGIN)

    def _add_chat_page(self, parsed: InstagramHTMLParser, show_header: bool = True):
        """
        Añade las páginas de conversación para un archivo HTML parseado.
        """
        self.pdf.add_page()
        self._set_dark_background()

        if show_header:
            self._add_section_header(parsed.conversation_title, parsed.filepath)

        if not parsed.messages:
            self.pdf.set_font("Helvetica", "I", 10)
            self.pdf.set_text_color(*COLOR_META)
            self.pdf.cell(0, 10, "No se encontraron mensajes en este archivo.", new_x="LMARGIN", new_y="NEXT")
            return

        # Detectar el "dueño" de la conversación (primer participante = tú)
        owner = parsed.participants[0] if parsed.participants else None

        for msg in parsed.messages:
            sender = msg.get("sender", "")
            content = msg.get("content", "").strip()
            timestamp = msg.get("timestamp", "")

            if not content:
                continue

            # Alineación: si el remitente es el propietario (o no hay info), va a la derecha
            is_right = (sender == owner) if owner and sender else False

            # Si hay 2+ participantes y sender no es owner → izquierda
            if len(parsed.participants) >= 2 and sender and sender != owner:
                is_right = False
            elif not sender:
                is_right = False

            self._draw_message_bubble(sender, content, timestamp, is_right)

    def generate_single_pdf(
        self,
        parsed_list: List[InstagramHTMLParser],
        output_path: str,
    ) -> bool:
        """
        Genera un único PDF combinando todos los archivos HTML parseados.
        """
        if not parsed_list:
            return False

        # Portada
        all_participants = []
        for p in parsed_list:
            for part in p.participants:
                if part not in all_participants:
                    all_participants.append(part)

        title = parsed_list[0].conversation_title or "Chat de Instagram"
        self._add_cover_page(title, all_participants, len(parsed_list))

        # Páginas de chat
        for parsed in parsed_list:
            show_header = len(parsed_list) > 1
            self._add_chat_page(parsed, show_header=show_header)

        try:
            self.pdf.output(output_path)
            print(f"[OK] PDF generado: {output_path}")
            return True
        except Exception as e:
            print(f"[ERROR] No se pudo guardar {output_path}: {e}")
            return False

    def generate_separate_pdfs(
        self,
        parsed_list: List[InstagramHTMLParser],
        output_dir: str,
    ) -> List[str]:
        """
        Genera un PDF separado por cada archivo HTML parseado.
        Devuelve la lista de rutas generadas.
        """
        generated = []
        for parsed in parsed_list:
            gen = ChatPDFGenerator()  # Nuevo generador por cada PDF
            gen._add_cover_page(
                parsed.conversation_title,
                parsed.participants,
                file_count=1,
            )
            gen._add_chat_page(parsed, show_header=False)

            stem = Path(parsed.filepath).stem
            out_path = os.path.join(output_dir, f"{stem}.pdf")
            try:
                gen.pdf.output(out_path)
                print(f"[OK] PDF generado: {out_path}")
                generated.append(out_path)
            except Exception as e:
                print(f"[ERROR] No se pudo guardar {out_path}: {e}")

        return generated


# ─────────────────────────────────────────────
#  Función principal
# ─────────────────────────────────────────────
def convert_html_to_pdf(
    html_files: List[str],
    output: Optional[str] = None,
    separados: bool = False,
    output_dir: Optional[str] = None,
) -> List[str]:
    """
    Convierte una lista de archivos HTML a PDF.

    Args:
        html_files:  Lista de rutas a archivos .html.
        output:      Ruta del PDF de salida cuando se combina todo en uno.
                     Si es None y separados=False, se genera 'chat_exportado.pdf'.
        separados:   Si True, genera un PDF por cada archivo HTML.
        output_dir:  Directorio donde guardar los PDFs separados.
                     Por defecto, el mismo directorio que el primer HTML.

    Returns:
        Lista de rutas de los PDFs generados.
    """
    if not html_files:
        print("[ERROR] No se proporcionaron archivos HTML.")
        return []

    # Parsear todos los archivos
    parsed_list = []
    for filepath in html_files:
        if not os.path.isfile(filepath):
            print(f"[AVISO] Archivo no encontrado: {filepath}")
            continue
        parser = InstagramHTMLParser(filepath)
        print(f"[*] Parseando: {filepath}")
        if parser.parse():
            print(f"    → {len(parser.messages)} mensajes encontrados")
            parsed_list.append(parser)
        else:
            print(f"    → No se encontraron mensajes (el archivo podría estar vacío o en formato no reconocido)")

    if not parsed_list:
        print("[ERROR] Ningún archivo HTML válido encontrado.")
        return []

    # Directorio de salida por defecto
    if output_dir is None:
        output_dir = os.path.dirname(os.path.abspath(parsed_list[0].filepath))

    generator = ChatPDFGenerator()

    if separados:
        return generator.generate_separate_pdfs(parsed_list, output_dir)
    else:
        if output is None:
            output = os.path.join(output_dir, "chat_exportado.pdf")
        success = generator.generate_single_pdf(parsed_list, output)
        return [output] if success else []


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Convierte chats de Instagram (message_1.html) a PDF.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python html_to_pdf.py message_1.html
  python html_to_pdf.py message_1.html message_2.html --output mi_chat.pdf
  python html_to_pdf.py message_*.html --separados
  python html_to_pdf.py message_1.html --output /ruta/salida/chat.pdf
        """,
    )
    parser.add_argument(
        "archivos",
        nargs="*",
        help="Archivos HTML a convertir (pueden usarse wildcards con comillas).",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Nombre/ruta del archivo PDF de salida (para modo combinado).",
    )
    parser.add_argument(
        "--separados", "-s",
        action="store_true",
        help="Genera un PDF separado por cada archivo HTML.",
    )
    parser.add_argument(
        "--dir", "-d",
        default=None,
        dest="output_dir",
        help="Directorio donde guardar los PDFs (por defecto, junto a los HTML).",
    )

    args = parser.parse_args()

    # Modo interactivo si no se pasaron archivos
    if not args.archivos:
        print("╔══════════════════════════════════════════════════╗")
        print("║   Conversor de Chat de Instagram a PDF          ║")
        print("╚══════════════════════════════════════════════════╝")
        print()
        entrada = input("Ingresa la ruta del/los archivo(s) HTML (separados por coma o espacio):\n> ").strip()
        if not entrada:
            print("[ERROR] No se indicaron archivos.")
            sys.exit(1)

        # Separar por coma o espacio
        import shlex
        archivos = [a.strip().strip('"').strip("'") for a in shlex.split(entrada.replace(",", " "))]

        modo = input("\n¿Combinar todos en un PDF? [S/n]: ").strip().lower()
        separados = modo == "n"

        output = None
        if not separados:
            nombre = input("\nNombre del PDF de salida [chat_exportado.pdf]: ").strip()
            output = nombre if nombre else None
    else:
        archivos = args.archivos
        separados = args.separados
        output = args.output

    # Expandir wildcards si el shell no lo hizo (Windows)
    import glob
    expanded = []
    for a in archivos:
        matches = glob.glob(a)
        expanded.extend(matches if matches else [a])

    results = convert_html_to_pdf(
        html_files=expanded,
        output=output,
        separados=separados,
        output_dir=args.output_dir if hasattr(args, "output_dir") else None,
    )

    if results:
        print(f"\n✓ Conversión completada. {len(results)} PDF(s) generado(s):")
        for r in results:
            print(f"  → {r}")
    else:
        print("\n✗ No se pudo generar ningún PDF.")
        sys.exit(1)


if __name__ == "__main__":
    main()
