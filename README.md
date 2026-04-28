# PortHawk – Escáner Inteligente de Puertos

![Python](https://img.shields.io/badge/python-3.6%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Nmap](https://img.shields.io/badge/requires-nmap-red)

PortHawk es un escáner de puertos de red construido sobre Nmap que automatiza el análisis de hosts, clasifica el nivel de riesgo de cada servicio y genera **reportes profesionales en TXT y HTML** listos para su visualización en el navegador.

---

## Características principales

- **Tres modos de escaneo** – rápido, balanceado y profundo (con detección de sistema operativo)
- **Clasificación automática de riesgos** – asigna niveles de severidad (INFO, BAJO, MEDIO, ALTO, CRÍTICO) a puertos conocidos
- **Doble salida de reportes** – archivo `.txt` detallado y página `.html` interactiva con etiquetas de riesgo por color
- **Huella digital del sistema operativo** – el escaneo profundo identifica el SO del objetivo
- **Fácilmente extensible** – la base de datos de riesgos se define en un diccionario simple
- **Interfaz de terminal limpia** – menú interactivo con banner ASCII

---

## Requisitos

- Python 3.6 o superior
- [Nmap](https://nmap.org) instalado y accesible en la ruta del sistema

  ## Instalación
  git clone https://github.com/tuusuario/porthawk.git
cd porthawk
chmod +x porthawk.py
./porthawk.py

## Uso
1. Rápido (descubrimiento básico)
2. Balanceado (detección de servicios y versiones)
3. Completo (Nmap profundo con scripts y detección de SO)
0. Salir


## Estructura
porthawk/
├── porthawk.py          # Script principal
├── reportes/            # Directorio de salida (autogenerado)
│   ├── reporte_*.txt
│   └── reporte_*.html
└── README.md
