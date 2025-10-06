# 🚨 Emergency Security Cleanup

**Plugin de emergencia para limpieza automática de malware después del compromiso del servidor**

[![Version](https://img.shields.io/badge/version-1.3.1-blue.svg)](https://github.com/aredos/emergency-cleanup)
[![WordPress](https://img.shields.io/badge/WordPress-5.0%2B-blue.svg)](https://wordpress.org/)
[![PHP](https://img.shields.io/badge/PHP-7.4%2B-green.svg)](https://php.net/)
[![License](https://img.shields.io/badge/license-GPL%20v2-orange.svg)](https://www.gnu.org/licenses/gpl-2.0.html)
[![Tested up to](https://img.shields.io/badge/tested%20up%20to-WP%206.7-brightgreen.svg)](https://wordpress.org/)

## 📋 Descripción

Emergency Security Cleanup es un plugin de WordPress diseñado específicamente para situaciones de emergencia después de un ataque de malware a nivel de servidor. Proporciona herramientas de escaneo y limpieza automática para restaurar la seguridad de tu sitio web de manera rápida y eficiente.

## ⚠️ Advertencia Importante

**Este plugin está diseñado para situaciones de emergencia después de un ataque de malware. Úsalo solo si tu sitio ha sido comprometido y necesitas una limpieza inmediata.**

- ⚠️ **Siempre haz un backup completo antes de usar este plugin**
- ⚠️ **Este plugin eliminará archivos automáticamente**
- ⚠️ **Elimina este plugin después de la limpieza**

## 🚀 Características Principales

### 🔍 **Detección Avanzada de Malware**
- **Archivos maliciosos específicos**: Detecta archivos conocidos de malware
- **Carpetas sospechosas**: Identifica directorios maliciosos
- **Plugins comprometidos**: Lista de plugins maliciosos conocidos
- **🆕 Carpetas NO registradas**: Detecta carpetas en `/plugins/` que NO están registradas en WordPress (backdoors ocultos)
- **Escaneo de contenido**: Analiza el contenido de archivos PHP en busca de código malicioso
- **Detección de backdoors**: Identifica patrones de código malicioso común
- **Whitelist inteligente**: Excluye plugins de seguridad legítimos (Wordfence, iThemes, Sucuri, etc.)
- **Detección de duplicados**: Identifica backups sospechosos (.bak, .old, .save)
- **Typosquatting**: Detecta archivos con nombres engañosos (adrnin.php, wp-lgin.php)
- **Análisis heurístico**: Compara conteo de archivos con baseline esperado
- **Detección de file spam**: Alerta sobre inyección masiva de archivos

### 🧹 **Limpieza Automática**
- **Eliminación segura**: Elimina archivos y carpetas maliciosos
- **Backup automático**: Crea copias de seguridad antes de eliminar
- **Limpieza de uploads**: Elimina archivos PHP maliciosos en la carpeta de uploads
- **Desactivación de plugins**: Desactiva y elimina plugins comprometidos

### 🗄️ **Verificación de Base de Datos**
- **Detección de inyecciones SQL**: Busca patrones de inyección en la base de datos
- **Análisis de tablas**: Identifica columnas y tablas sospechosas
- **Contenido malicioso inteligente**: Escanea posts en busca de código ejecutable (no solo menciones)
- **Ignora contenido educativo**: Distingue entre tutoriales y código malicioso real
- **Detecta bloques de código**: No alerta sobre ejemplos en `<pre>` o `<code>`

### ✅ **Verificación de Integridad**
- **Archivos core de WordPress**: Verifica la integridad de archivos principales
- **Análisis de .htaccess**: Detecta modificaciones maliciosas
- **Verificación de tamaño**: Identifica archivos core sospechosos

### 🎨 **Interfaz Intuitiva**
- **Panel de administración**: Interfaz clara y fácil de usar
- **Opciones configurables**: Activa/desactiva funciones según necesites
- **Barra de progreso**: Feedback visual durante el escaneo
- **Generador de contraseñas**: Crea contraseñas seguras
- **Lista de verificación**: Guía paso a paso post-limpieza

## 📦 Instalación

### Instalación Manual

1. **Descarga el plugin** desde este repositorio
2. **Sube el archivo** `emergency-cleanup.php` a la carpeta `/wp-content/plugins/`
3. **Activa el plugin** desde el panel de administración de WordPress
4. **Accede a la configuración** en "Configuración > Emergency Cleanup"

### Instalación por FTP

```bash
# Conecta por FTP a tu servidor
# Navega a /wp-content/plugins/
# Sube el archivo emergency-cleanup.php
# Activa desde el panel de WordPress
```

## 🛠️ Uso

### 1. **Acceso al Plugin**
- Ve a **Configuración > Emergency Cleanup** en tu panel de WordPress
- Verás el panel principal con todas las opciones disponibles

### 2. **Configuración de Opciones**
Antes de ejecutar el escaneo, configura las opciones:

- ✅ **Crear backup antes de eliminar** (recomendado)
- ✅ **Escanear contenido de archivos** (recomendado)
- ✅ **Verificar base de datos** (recomendado)
- ✅ **Verificar integridad WordPress** (recomendado)

### 3. **Ejecutar Escaneo**
- **Escaneo Completo**: Detecta malware y permite limpieza
- **Solo Escanear**: Diagnóstico sin eliminar archivos

### 4. **Limpieza Automática**
- Si se detecta malware, aparecerá el botón "Iniciar Limpieza"
- **Confirma la acción** - no se puede deshacer
- El plugin eliminará automáticamente los archivos maliciosos

### 5. **Post-Limpieza**
Sigue la lista de verificación proporcionada:

#### **Acciones Críticas:**
- [ ] Cambiar contraseña WordPress admin
- [ ] Cambiar contraseña base de datos
- [ ] Cambiar credenciales FTP
- [ ] Regenerar claves seguridad WordPress
- [ ] Reconectar Jetpack (si aplica)

#### **Seguridad Futura:**
- [ ] Instalar Wordfence Security
- [ ] Instalar WP Activity Log
- [ ] Configurar backups automáticos
- [ ] Actualizar WordPress y plugins
- [ ] Eliminar este plugin tras limpieza

## 🔧 Configuración Avanzada

### Patrones de Detección

El plugin incluye patrones predefinidos para detectar:

- **Backdoors**: `eval()`, `base64_decode()`, `shell_exec()`, `system()`
- **Inyecciones SQL**: `union select`, `drop table`, `insert into`
- **Código ofuscado**: Variables con contenido base64 sospechoso
- **Criptominería**: `cryptonight`, `monero`, `bitcoin`, `coinhive`
- **Scripts de spam**: `mail()`, `wp_mail()`, `phpmailer`

### Archivos y Carpetas Detectados

#### **Archivos Maliciosos:**
- `index.html`, `index.html_bak`
- `htaccess_bak`
- `public_html.rar`, `wp-content.rar`

#### **Carpetas Maliciosas:**
- `.usermin`, `awstats-icon`
- `icon`, `stats`, `cgi-bin`

#### **Plugins Maliciosos:**
- `cardoza-3d-tag-cloud`, `cphbgsu`
- `Fix`, `Hellos`, `wp-reforming-itself`
- `advanced-nocaptcha-recaptcha-old`
- `google-pagespeed-insights`
- Y más...

## 🧬 Parámetros Técnicos y Algoritmos

### 📊 **Sistema de Análisis Heurístico**

El plugin utiliza análisis heurístico avanzado para detectar anomalías comparando el conteo de archivos real con un baseline esperado.

#### **Baseline Esperado (Promedios de la Industria)**

| Tipo | Promedio de Archivos PHP | Tolerancia |
|------|-------------------------|------------|
| **Plugin pequeño** | 30-50 archivos | ±50% |
| **Plugin medio** | 100-150 archivos | ±50% |
| **Plugin grande** | 500-1,000 archivos | ±50% |
| **Promedio general** | **120 archivos/plugin** | ±50% |
| | |
| **Tema simple** | 20-40 archivos | ±50% |
| **Tema complejo** | 80-120 archivos | ±50% |
| **Promedio general** | **60 archivos/tema** | ±50% |
| | |
| **Uploads** | **0-5 archivos** (solo protección) | 0% |

#### **Fórmulas de Cálculo**

```php
// Cálculo del baseline esperado
Expected_Plugins = Total_Plugins × 120 archivos
Expected_Themes = Total_Themes × 60 archivos
Expected_Uploads = 5 archivos (máximo)

// Cálculo de desviación
Deviation = ((Actual - Expected) / Expected) × 100%
```

#### **Niveles de Severidad**

| Desviación | Severidad | Acción |
|------------|-----------|--------|
| **±50%** | ✅ Normal | No alertar |
| **>50%** | 🟡 Media | Revisar manualmente |
| **>100%** | 🟠 Alta | Posible malware |
| **>200%** | 🔴 Crítica | Probable ataque |
| **Uploads >10** | 🟠 Alta | Revisar todos los archivos |
| **Uploads >100** | 🔴 Crítica | FILE SPAM - Ataque en curso |

#### **Ejemplos de Detección**

**✅ Caso Normal:**
```
Plugins: 10 instalados
Esperado: 10 × 120 = 1,200 archivos
Real: 1,156 archivos
Desviación: -3.7% ✅ NORMAL
```

**🚨 Caso de Ataque:**
```
Plugins: 10 instalados
Esperado: 10 × 120 = 1,200 archivos
Real: 3,456 archivos
Desviación: +188% 🚨 CRÍTICO

Uploads:
Esperado: 5 archivos
Real: 847 archivos
Desviación: +16,840% 🚨 FILE SPAM DETECTADO
```

### 🔍 **Detección de Duplicados y Backups**

#### **Patrones de Archivos Sospechosos**

El plugin detecta **15 patrones** de nombres de archivos que indican backups o duplicados sospechosos:

| Patrón | Riesgo | Ejemplo |
|--------|--------|---------|
| `.bak` | 🔴 Alto | `wp-config.php.bak` |
| `.backup` | 🔴 Alto | `index.php.backup` |
| `.old` | 🔴 Alto | `wp-settings.php.old` |
| `.save` | 🟠 Medio | `.htaccess.save` |
| `.copy` | 🟠 Medio | `admin.php.copy` |
| `.orig` | 🟠 Medio | `wp-load.php.orig` |
| `.tmp` | 🟡 Bajo | `config.tmp` |
| `_backup` | 🔴 Alto | `database_backup.sql` |
| `-backup` | 🔴 Alto | `site-backup.php` |
| `-old` | 🔴 Alto | `login-old.php` |
| `-copy` | 🟠 Medio | `index-copy.php` |
| `.suspected` | 🔴 Alto | `malware.suspected` |
| `.infected` | 🔴 Alto | `file.infected` |
| `.virus` | 🔴 Alto | `backdoor.virus` |

#### **Archivos Críticos Protegidos**

Archivos que **NUNCA** deberían tener backups en producción:

- `wp-config.php` - Contiene credenciales de base de datos
- `wp-settings.php` - Configuración principal de WordPress
- `wp-load.php` - Archivo de carga de WordPress
- `.htaccess` - Configuración del servidor

**⚠️ PELIGRO:** Un backup como `wp-config.php.bak` puede ser **descargable públicamente** y exponer todas las credenciales.

### 🎭 **Detección de Typosquatting**

El plugin detecta archivos con nombres engañosos que imitan archivos legítimos:

| Legítimo | Malicioso | Técnica |
|----------|-----------|---------|
| `admin.php` | `adrnin.php` | Cambio de letra (m→r+n) |
| `wp-login.php` | `wp-lgin.php` | Letra faltante |
| `wp-login.php` | `wp-lgoin.php` | Letras transpuestas |
| `wp-config.php` | `wp-contig.php` | Letra cambiada (f→t) |
| `config.php` | `cofig.php` | Letra faltante |
| `config.php` | `confg.php` | Letra faltante |

### 🛡️ **Verificación Avanzada de index.php**

El plugin verifica **12 aspectos críticos** antes de considerar un `index.php` como legítimo:

#### **Verificaciones de Seguridad**

1. ✅ **Permisos del archivo** - Rechaza permisos 777, 666, 775, 776
2. ✅ **Tamaño del archivo** - Archivos de 0 bytes son legítimos
3. ✅ **BOM (Byte Order Mark)** - Detecta caracteres ocultos
4. ✅ **Caracteres binarios** - Detecta ofuscación con bytes 0x00-0x1F
5. ✅ **Funciones peligrosas** - Rechaza eval, base64_decode, system, exec, etc.
6. ✅ **Patrones conocidos seguros** - Acepta solo patrones WordPress estándar
7. ✅ **Longitud de código** - Archivos muy pequeños sin funciones peligrosas
8. ✅ **Comentarios vs código** - Distingue comentarios de código ejecutable

#### **Patrones Seguros Aceptados**

```php
// ✅ Archivos index.php LEGÍTIMOS:
""                              // Vacío (0 bytes)
"<?php"                         // Solo apertura PHP
"<?php // Silence is golden"   // WordPress estándar
"<?php // Silence is golden."  // WordPress estándar con punto
"<?php\n/**\n * Empty index for security\n */" // Comentario de seguridad
```

#### **Patrones Maliciosos Rechazados**

```php
// ❌ Archivos index.php MALICIOSOS:
"<?php eval($_POST['x']);"              // eval con variable superglobal
"<?php system($_GET['cmd']);"           // Ejecución de comandos
"<?php base64_decode('...');"           // Ofuscación base64
"<?php   " + caracteres invisibles      // Espacios Unicode ocultos
Archivos con permisos 777                // Permisos anormales
```

### 📋 **Patrones de Código Malicioso**

El plugin utiliza **25+ patrones regex** refinados para detectar malware:

#### **Backdoors con Ofuscación (Crítico)**
```regex
/eval\s*\(\s*base64_decode\s*\(/i
/eval\s*\(\s*gzinflate\s*\(/i
/eval\s*\(\s*gzuncompress\s*\(/i
/eval\s*\(\s*str_rot13\s*\(/i
/assert\s*\(\s*base64_decode\s*\(/i
```

#### **Ejecución de Comandos (Alto Riesgo)**
```regex
/system\s*\(\s*\$[_a-zA-Z]/i
/exec\s*\(\s*\$[_a-zA-Z]/i
/shell_exec\s*\(\s*\$[_a-zA-Z]/i
/passthru\s*\(\s*\$[_a-zA-Z]/i
/proc_open\s*\(/i
/popen\s*\(/i
```

#### **Variables Superglobales Sospechosas**
```regex
/\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*[\'"]\w+[\'"]\s*\]\s*\(\s*\$/i
/create_function\s*\(\s*[\'"]\s*\$\w+\s*[\'"]/i
```

#### **Strings Base64 Largos (Ofuscación)**
```regex
/["\'][A-Za-z0-9+\/]{200,}={0,2}["\']/i
```

#### **Backdoors Conocidos**
```regex
/c99shell/i
/r57shell/i
/webshell/i
/FilesMan/i
```

#### **Criptominería**
```regex
/coinhive\.min\.js/i
/crypto-loot/i
/cryptonight\s*\(/i
/new\s+Miner\s*\(/i
```

### 🧠 **Sistema de Confianza Multi-Patrón**

Para reducir falsos positivos, el plugin usa un sistema de "confianza":

#### **Regla de Dos Patrones**
```
Un archivo es malicioso SI:
  - Coincide con 2+ patrones normales, O
  - Coincide con 1 patrón crítico
```

#### **Patrones Críticos (1 match = malicioso)**
- `eval(base64_decode(`
- `eval(gzinflate(`
- `c99shell`, `r57shell`, `webshell`

#### **Whitelist de Archivos Legítimos**
```php
// Archivos que pueden tener código "sospechoso" pero son legítimos:
- PHPMailer
- class-phpmailer.php
- class-smtp.php
- wp-mail.php
```

#### **Whitelist de Plugins de Seguridad**
```php
// Plugins excluidos del escaneo (contienen código de seguridad legítimo):
- wordfence           // Wordfence Security
- ithemes-security    // iThemes Security  
- sucuri-scanner      // Sucuri Security
- all-in-one-wp-security
- jetpack
- akismet
```

### 🎯 **Optimizaciones de Rendimiento**

| Optimización | Valor | Razón |
|-------------|-------|-------|
| **Tamaño máximo de archivo** | 1 MB | Evitar timeout en archivos grandes |
| **Límite de archivos por directorio** | 5,000 | Prevenir agotamiento de memoria |
| **Directorios ignorados** | node_modules, vendor, .git | No escanear librerías |
| **Archivos escaneados** | Solo .php | Malware típicamente en PHP |
| **Backup máximo por sesión** | Ilimitado | Respaldos completos |

## 📊 Logs y Reportes

### **Log de Escaneo**
- Muestra todos los archivos y carpetas detectados
- Indica el estado de cada elemento (limpio/malicioso)
- Proporciona estadísticas del escaneo

### **Log de Limpieza**
- Registra cada archivo eliminado
- Muestra errores si los hay
- Cuenta total de elementos eliminados

### **Backup Log**
- Lista archivos respaldados
- Ubicación del directorio de backup
- Timestamp de creación

## 🔒 Seguridad

### **Medidas de Seguridad Implementadas**
- ✅ Verificación de nonce para prevenir CSRF
- ✅ Verificación de permisos (`manage_options`)
- ✅ Sanitización de datos de entrada
- ✅ Validación de operaciones
- ✅ Prevención de acceso directo

### **Recomendaciones de Seguridad**
- 🔐 Cambia todas las contraseñas después de la limpieza
- 🔑 Regenera las claves de seguridad de WordPress
- 🛡️ Instala un plugin de seguridad como Wordfence
- 📋 Configura logs de actividad
- 💾 Establece backups automáticos regulares

## 🆘 Solución de Problemas

### **Error: "Security check failed"**
- Recarga la página y vuelve a intentar
- Verifica que tengas permisos de administrador

### **Error: "Insufficient permissions"**
- Asegúrate de estar logueado como administrador
- Verifica que tu usuario tenga permisos `manage_options`

### **El plugin no detecta malware**
- Verifica que las opciones de escaneo estén activadas
- Ejecuta un escaneo completo con todas las opciones
- Considera usar herramientas adicionales como Wordfence

### **Error al crear backup**
- Verifica permisos de escritura en `/wp-content/`
- Asegúrate de que hay espacio suficiente en disco
- El plugin continuará sin backup si hay errores

## 📈 Rendimiento

### **Optimizaciones Incluidas**
- Escaneo recursivo eficiente
- Límites de archivos para evitar timeouts
- Procesamiento por lotes
- Verificaciones de memoria

### **Recomendaciones de Rendimiento**
- Ejecuta el escaneo en horarios de bajo tráfico
- Considera aumentar el límite de memoria PHP si es necesario
- El escaneo de contenido puede ser lento en sitios grandes

## 🤝 Contribuciones

¡Las contribuciones son bienvenidas! Este es un proyecto de código abierto y valoramos cualquier aporte que ayude a mejorar la seguridad de WordPress.

### **Reportar Problemas**

Si encuentras un bug o tienes una sugerencia:

1. **Abre un [Issue](https://github.com/aredos/emergency-cleanup/issues/new)** en GitHub
2. **Describe el problema detalladamente**
   - ¿Qué estabas intentando hacer?
   - ¿Qué esperabas que pasara?
   - ¿Qué pasó en realidad?
3. **Incluye información del sistema:**
   - Versión de WordPress
   - Versión de PHP
   - Versión del plugin
   - Sistema operativo del servidor
4. **Proporciona logs de error** si están disponibles

### **Contribuir al Código**

Para contribuir con código, sigue estos pasos:

#### 1. **Fork el Repositorio**
```bash
# Haz clic en el botón "Fork" en GitHub
# Luego clona TU fork
git clone https://github.com/TU-USUARIO/emergency-cleanup.git
cd emergency-cleanup
```

#### 2. **Crea una Rama para tu Feature**
```bash
# Crea y cambia a una nueva rama
git checkout -b feature/nombre-descriptivo

# Ejemplos de nombres de rama:
# - feature/deteccion-nuevos-backdoors
# - fix/corregir-falso-positivo
# - docs/actualizar-readme
```

#### 3. **Implementa tus Cambios**
```bash
# Haz tus cambios
# Asegúrate de seguir los estándares de código de WordPress

# Añade tus cambios
git add .

# Commit con mensaje descriptivo
git commit -m "feat: descripción clara del cambio"
```

#### 4. **Push a tu Fork**
```bash
git push origin feature/nombre-descriptivo
```

#### 5. **Crea un Pull Request**
- Ve a tu fork en GitHub
- Haz clic en "Compare & pull request"
- Describe tus cambios detalladamente
- Espera la revisión y aprobación

### **Guías de Contribución**

#### **Estándares de Código**
- ✅ Sigue los [WordPress Coding Standards](https://developer.wordpress.org/coding-standards/wordpress-coding-standards/)
- ✅ Usa nombres de variables descriptivos en español (como el resto del código)
- ✅ Comenta tu código, especialmente en áreas complejas
- ✅ Asegúrate de que no haya errores de linting

#### **Buenas Prácticas**
- ✅ **Un cambio por Pull Request** - No mezcles múltiples features
- ✅ **Tests** - Si es posible, añade casos de prueba
- ✅ **Documentación** - Actualiza el README si añades funcionalidades
- ✅ **Commits descriptivos** - Usa mensajes claros
  ```
  feat: añadir detección de nuevo tipo de malware
  fix: corregir falso positivo en PHPMailer
  docs: actualizar ejemplos en README
  ```

#### **Proceso de Revisión**
1. Tu Pull Request será revisado por el mantenedor
2. Puede haber comentarios o solicitudes de cambios
3. Una vez aprobado, será fusionado a la rama `main`
4. ¡Tu contribución será parte del proyecto! 🎉

### **Tipos de Contribuciones Bienvenidas**

- 🐛 **Corrección de Bugs** - Arregla problemas existentes
- ✨ **Nuevas Funcionalidades** - Añade nuevas detecciones de malware
- 📝 **Documentación** - Mejora el README, comentarios, ejemplos
- 🎨 **Mejoras de UI** - Mejora la interfaz del plugin
- 🔍 **Detección de Malware** - Añade nuevos patrones o técnicas
- ⚡ **Optimización** - Mejora el rendimiento del plugin

### **Importante**

> **Nota:** Todos los Pull Requests requieren aprobación del mantenedor antes de ser fusionados. Esto garantiza la calidad y seguridad del código que protege sitios WordPress.

### **¿Necesitas Ayuda?**

- 💬 Abre un [Discussion](https://github.com/aredos/emergency-cleanup/discussions) para preguntas generales
- 📧 Contacta al mantenedor: [info@aredos.com](mailto:info@aredos.com)
- 📖 Consulta la [documentación de WordPress](https://developer.wordpress.org/)

## 📄 Licencia

Este plugin está licenciado bajo la **GPL v2** o posterior.

```
Emergency Security Cleanup
Copyright (C) 2024 Aredos

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.
```

## 👨‍💻 Autor

**Aredos** - Desarrollador de WordPress

- 🌐 **Sitio Web**: [Tu sitio web]
- 📧 **Email**: [info@aredos.com]
- 🐙 **GitHub**: [@aredos]

## 🙏 Agradecimientos

- Comunidad de WordPress por las mejores prácticas de seguridad
- Desarrolladores de plugins de seguridad por la inspiración
- Todos los usuarios que han reportado mejoras

## 📞 Soporte

Para soporte técnico:

1. **GitHub Issues**: Para bugs y sugerencias
2. **Email**: [info@aredos.com]
3. **Documentación**: Consulta este README

---

## ⚡ Changelog

Para ver el historial completo de cambios y versiones, consulta el archivo **[CHANGELOG.md](CHANGELOG.md)**.

### Última Versión: **1.3.1**

**✅ Cumplimiento WordPress.org Coding Standards**
- Correcciones de Text Domain
- Escape de seguridad en todas las salidas
- Placeholders ordenados en traducciones
- Comentarios translators añadidos
- Supresión justificada de consultas directas a BD

[Ver changelog completo →](CHANGELOG.md)

---

**⚠️ Recuerda: Este plugin es para emergencias. Elimínalo después de la limpieza y mantén tu sitio seguro con herramientas de seguridad permanentes.**
