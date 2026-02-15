# Usar una imagen base de Python ligera
FROM python:3.11-slim

# Instalar dependencias del sistema necesarias para compilar yara-python y herramientas de red
RUN apt-get update && apt-get install -y \\
    build-essential \\
    libyara-dev \\
    iputils-ping \\
    && rm -rf /var/lib/apt/lists/*

# Establecer el directorio de trabajo
WORKDIR /app

# Copiar archivos de requerimientos e instalar dependencias de Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el resto del código
COPY . .

# Comando por defecto para ejecutar el diagnóstico
CMD ["python", "run_full_diagnostic.py"]
