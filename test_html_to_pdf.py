#!/usr/bin/env python3
"""
Tests para el conversor HTML → PDF de chats de Instagram.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from html_to_pdf import InstagramHTMLParser, ChatPDFGenerator, convert_html_to_pdf

# ─────────────────────────────────────────────────────────────────────────────
#  HTML de ejemplo con formato de exportación de Instagram
# ─────────────────────────────────────────────────────────────────────────────
SAMPLE_INSTAGRAM_HTML = """<!DOCTYPE html>
<html>
<head>
  <title>Chat con usuario_ejemplo</title>
  <meta charset="utf-8">
</head>
<body>
<div role="main">
  <div class="_a6-h _a6-i">Chat con usuario_ejemplo</div>
  <div class="_a6-h _a6-i">
    Participantes: yo_usuario, usuario_ejemplo
  </div>
  <div class="_3-95 _2pio _a6-h _a6-i">
    <div class="_2ph_ _a6-p">
      <div class="_3-95 _2pi2 _a6-h _a6-i">
        <div class="_3-96 _a6-p">
          <div class="_3-95 _2pi0 _a6-h _a6-i">yo_usuario</div>
          <div class="_3-96 _a6-p">Hola, ¿cómo estás?</div>
          <div class="_3-94 _a6-o">13 de enero de 2024, 10:30</div>
        </div>
      </div>
    </div>
    <div class="_2ph_ _a6-p">
      <div class="_3-95 _2pi2 _a6-h _a6-i">
        <div class="_3-96 _a6-p">
          <div class="_3-95 _2pi0 _a6-h _a6-i">usuario_ejemplo</div>
          <div class="_3-96 _a6-p">¡Muy bien! ¿Y tú?</div>
          <div class="_3-94 _a6-o">13 de enero de 2024, 10:32</div>
        </div>
      </div>
    </div>
    <div class="_2ph_ _a6-p">
      <div class="_3-95 _2pi2 _a6-h _a6-i">
        <div class="_3-96 _a6-p">
          <div class="_3-95 _2pi0 _a6-h _a6-i">yo_usuario</div>
          <div class="_3-96 _a6-p">Todo bien, gracias por preguntar.</div>
          <div class="_3-94 _a6-o">13 de enero de 2024, 10:33</div>
        </div>
      </div>
    </div>
  </div>
</div>
</body>
</html>
"""

SAMPLE_GENERIC_HTML = """<!DOCTYPE html>
<html>
<head><title>Conversación</title></head>
<body>
  <p>Mensaje de prueba número uno.</p>
  <p>Segundo mensaje en el chat.</p>
  <div>Un div con contenido de chat.</div>
</body>
</html>
"""


class TestInstagramHTMLParser(unittest.TestCase):
    """Tests para el parser de HTML de Instagram."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write_html(self, content: str, filename: str = "message_1.html") -> str:
        path = os.path.join(self.tmpdir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def test_parse_instagram_format(self):
        """El parser debe extraer mensajes del formato típico de Instagram."""
        path = self._write_html(SAMPLE_INSTAGRAM_HTML)
        parser = InstagramHTMLParser(path)
        result = parser.parse()

        self.assertTrue(result, "El parser debe devolver True cuando encuentra mensajes")
        self.assertGreater(len(parser.messages), 0, "Debe haber al menos un mensaje")

    def test_conversation_title(self):
        """Debe extraer el título de la conversación."""
        path = self._write_html(SAMPLE_INSTAGRAM_HTML)
        parser = InstagramHTMLParser(path)
        parser.parse()
        self.assertTrue(parser.conversation_title, "El título no debe estar vacío")

    def test_message_structure(self):
        """Cada mensaje debe tener las claves 'sender', 'content' y 'timestamp'."""
        path = self._write_html(SAMPLE_INSTAGRAM_HTML)
        parser = InstagramHTMLParser(path)
        parser.parse()

        for msg in parser.messages:
            self.assertIn("sender", msg)
            self.assertIn("content", msg)
            self.assertIn("timestamp", msg)
            self.assertTrue(msg["content"], "El contenido del mensaje no debe estar vacío")

    def test_parse_generic_html(self):
        """El parser genérico debe manejar HTML sin formato de Instagram."""
        path = self._write_html(SAMPLE_GENERIC_HTML, "generic.html")
        parser = InstagramHTMLParser(path)
        result = parser.parse()

        # El parser genérico puede tener éxito o no, pero no debe lanzar excepción
        self.assertIsInstance(result, bool)

    def test_file_not_found(self):
        """El parser debe devolver False si el archivo no existe."""
        parser = InstagramHTMLParser("/ruta/inexistente/message_1.html")
        result = parser.parse()
        self.assertFalse(result)

    def test_multiple_messages_no_duplicates(self):
        """Los mensajes no deben estar duplicados."""
        path = self._write_html(SAMPLE_INSTAGRAM_HTML)
        parser = InstagramHTMLParser(path)
        parser.parse()

        contents = [m["content"] for m in parser.messages]
        self.assertEqual(len(contents), len(set(contents)), "No deben existir mensajes duplicados")


class TestChatPDFGenerator(unittest.TestCase):
    """Tests para el generador de PDF."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_parser(self) -> InstagramHTMLParser:
        path = os.path.join(self.tmpdir, "message_1.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(SAMPLE_INSTAGRAM_HTML)
        parser = InstagramHTMLParser(path)
        parser.parse()
        return parser

    def test_generate_single_pdf(self):
        """Debe generar un PDF cuando se combina un archivo."""
        parser = self._make_parser()
        gen = ChatPDFGenerator()
        out = os.path.join(self.tmpdir, "output.pdf")
        result = gen.generate_single_pdf([parser], out)

        self.assertTrue(result, "generate_single_pdf debe devolver True")
        self.assertTrue(os.path.isfile(out), "El archivo PDF debe existir")
        self.assertGreater(os.path.getsize(out), 0, "El PDF no debe estar vacío")

    def test_generate_separate_pdfs(self):
        """Debe generar PDFs separados para cada archivo."""
        parser = self._make_parser()
        gen = ChatPDFGenerator()
        results = gen.generate_separate_pdfs([parser], self.tmpdir)

        self.assertEqual(len(results), 1)
        self.assertTrue(os.path.isfile(results[0]))
        self.assertGreater(os.path.getsize(results[0]), 0)

    def test_generate_combined_multiple(self):
        """Debe combinar varios parsers en un único PDF."""
        # Crear dos archivos
        parsers = []
        for i in range(2):
            path = os.path.join(self.tmpdir, f"message_{i+1}.html")
            with open(path, "w", encoding="utf-8") as f:
                f.write(SAMPLE_INSTAGRAM_HTML)
            p = InstagramHTMLParser(path)
            p.parse()
            parsers.append(p)

        gen = ChatPDFGenerator()
        out = os.path.join(self.tmpdir, "combined.pdf")
        result = gen.generate_single_pdf(parsers, out)

        self.assertTrue(result)
        self.assertTrue(os.path.isfile(out))

    def test_empty_parser_list(self):
        """No debe generar nada con lista vacía."""
        gen = ChatPDFGenerator()
        out = os.path.join(self.tmpdir, "empty.pdf")
        result = gen.generate_single_pdf([], out)
        self.assertFalse(result)


class TestConvertHtmlToPdf(unittest.TestCase):
    """Tests de integración para la función convert_html_to_pdf."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.html_path = os.path.join(self.tmpdir, "message_1.html")
        with open(self.html_path, "w", encoding="utf-8") as f:
            f.write(SAMPLE_INSTAGRAM_HTML)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_convert_single_file(self):
        """Debe convertir un solo archivo HTML a PDF."""
        out = os.path.join(self.tmpdir, "result.pdf")
        results = convert_html_to_pdf([self.html_path], output=out)

        self.assertEqual(len(results), 1)
        self.assertTrue(os.path.isfile(results[0]))

    def test_convert_no_files(self):
        """Debe devolver lista vacía si no hay archivos."""
        results = convert_html_to_pdf([])
        self.assertEqual(results, [])

    def test_convert_nonexistent_file(self):
        """Debe ignorar archivos que no existen."""
        results = convert_html_to_pdf(["/ruta/falsa/message_1.html"])
        self.assertEqual(results, [])

    def test_convert_separate_mode(self):
        """En modo separado, debe generar un PDF por archivo."""
        results = convert_html_to_pdf(
            [self.html_path],
            separados=True,
            output_dir=self.tmpdir,
        )
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].endswith(".pdf"))

    def test_output_default_name(self):
        """Si no se especifica nombre, debe usar 'chat_exportado.pdf'."""
        results = convert_html_to_pdf(
            [self.html_path],
            output_dir=self.tmpdir,
        )
        self.assertEqual(len(results), 1)
        self.assertTrue(os.path.basename(results[0]) == "chat_exportado.pdf")


def run_all_tests():
    """Ejecuta todos los tests del conversor HTML → PDF."""
    print("╔══════════════════════════════════════════════════════════╗")
    print("║       TESTS: Conversor de Chat Instagram a PDF          ║")
    print("╚══════════════════════════════════════════════════════════╝")

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for cls in (TestInstagramHTMLParser, TestChatPDFGenerator, TestConvertHtmlToPdf):
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
