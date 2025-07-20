# mspoffer DNS & ARP Spoofer Pro 🚀

![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![License](https://img.shields.io/badge/License-OPEN%20SOURCE-green)
![Version](https://img.shields.io/badge/Version-1.0-orange)
![Platform](https://img.shields.io/badge/Platform-Windows%2FLinux-lightgrey)

Herramienta avanzada de seguridad para pruebas de penetración en redes locales mediante ARP Spoofing y DNS Spoofing, con interfaz gráfica moderna y múltiples funciones adicionales.

## 📌 Características Principales

- **ARP Spoofing** avanzado con técnicas de envenenamiento de caché ARP
- **DNS Spoofing** con redirección personalizada de dominios
- **Bloqueo de Internet** para objetivos específicos
- **Sniffer de credenciales** para capturar información sensible
- **Escáner de red** integrado con detección de dispositivos
- **Protección ARP** para defenderte contra ataques similares
- **Interfaz gráfica moderna** con modo oscuro
- **Registro completo** de todas las actividades
- **Multiplataforma** (Windows y Linux)

## ⚙️ Requisitos del Sistema

- Python 3.7 o superior
- Scapy 2.4.5 o superior
- Tkinter (generalmente incluido con Python)
- PIL/Pillow (para soporte de imágenes)
- Sistema operativo: Windows 10/11 o Linux

## 📦 Instalación

1. Clona el repositorio:
   ```bash
   git clone https://github.com/M-Societyy/mspoffer.git
   cd mspoffer
   ```

2. Instala las dependencias:
   ```bash
   pip install -r requirements.txt
   ```

   O instálalas manualmente:
   ```bash
   pip install scapy pillow
   ```

3. Ejecuta la aplicación:
   ```python
   python3 mspoffer.py
   ```

## 🖥️ Uso Básico

1. **Configuración inicial**:
   - Selecciona tu interfaz de red
   - Escanea la red para descubrir dispositivos
   - Selecciona tu objetivo

2. **Ataques disponibles**:
   - ARP Spoofing: Intercepta el tráfico entre el objetivo y el gateway
   - DNS Spoofing: Redirige dominios específicos a tu IP
   - Bloqueo de Internet: Deniega el acceso a Internet al objetivo

3. **Herramientas adicionales**:
   - Sniffer de credenciales
   - Escáner de puertos
   - Analizador de conexiones de red

## ⚠️ Disclaimer Legal

**ADVERTENCIA**: Este software está diseñado únicamente para pruebas de seguridad éticas en redes donde tienes permiso explícito para realizar estas acciones. El uso no autorizado de esta herramienta para interceptar, alterar o bloquear comunicaciones de red es ilegal y puede acarrear consecuencias penales.

El autor no se hace responsable del mal uso de esta herramienta. Úsala únicamente en entornos controlados y con el consentimiento de todas las partes involucradas.

## 🐛 Problemas Conocidos

- **En sistemas Linux** puede requerir ejecución con privilegios root
- **En algunas distribuciones** pueden faltar dependencias de Tkinter
- **Las interfaces WiFi** pueden requerir configuración adicional
- **Las protecciones ARP modernas** (como arpwatch) pueden detectar el ataque

## 🔧 Solución de Problemas

1. **Error con Scapy**:
   ```
   ModuleNotFoundError: No module named 'scapy'
   ```
   Solución: Instala Scapy correctamente con `pip install scapy`

2. **Problemas de permisos**:
   ```
   PermissionError: [Errno 1] Operation not permitted
   ```
   Solución: Ejecuta el script con privilegios elevados (sudo/Administrador)

3. **Interfaz no encontrada**:
   ```
   ValueError: Unknown interface: eth0
   ```
   Solución: Verifica el nombre de tu interfaz con `ifconfig` (Linux) o `ipconfig` (Windows)

## 🌟 Características Avanzadas

- **Técnicas de spoofing mejoradas** que evitan detección básica
- **Base de datos de vendors** para identificación de dispositivos
- **Auto-restauración** de tablas ARP al cerrar la aplicación
- **Sistema de logging completo** con marca de tiempo
- **Interfaz modular** fácil de extender

## 📄 Licencia

Este proyecto está bajo licencia OPEN SOURCE. Puedes usarlo, modificarlo y distribuirlo libremente, siempre manteniendo los créditos al autor original.

## ✉️ Soporte y Contacto

Para soporte técnico, reporte de errores o colaboraciones:

- **Discord**: [https://discord.gg/9QRngbrMKS](https://discord.gg/9QRngbrMKS)

## 👨‍💻 Contribuciones

Las contribuciones son bienvenidas. Puedes publicar tu version en el servidor de discord

## 📌 Versiones

- **v1.0** (2025-20-07): Versión inicial con todas las características básicas

---

**NOTA**: Esta herramienta debe usarse únicamente con fines educativos y en entornos controlados con el debido consentimiento. El uso no autorizado puede violar leyes locales e internacionales.
```
