## 🔐 `pgtlsinfo()`

`pgtlsinfo` es una función de PostgreSQL diseñada para **inspeccionar certificados X.509 y servidores PostgreSQL con SSL/TLS habilitado**, obteniendo información técnica completa del entorno de seguridad y conexión.


### 🛡️ **Requisitos**

- PostgreSQL con PL/pgSQL habilitado.
- Acceso al sistema de archivos (si inspecciona certificados locales).
- `openssl` debe estar disponible en el entorno de ejecución.
 

---

### 📦 **Valores que rotorna la función**

```sql
pgtlsinfo(TEXT)
RETURNS TABLE (
  ip_server INET,
  port INT,
  connect_server BOOLEAN,
  tls_enabled BOOLEAN,
  tls_version TEXT,
  cipher TEXT,
  issuer TEXT,
  subject TEXT,
  key_usage TEXT,
  extended_key_usage TEXT,
  alternative_name TEXT,
  basic_constraints TEXT,
  cert_type TEXT,
  date_before TIMESTAMP,
  date_after TIMESTAMP,
  path TEXT,
  is_file BOOLEAN,
  certificate TEXT,
  openssl_output TEXT
)
```
--- 


### 📖 **Descripción de columnas**

| Columna              | Descripción                                                                 |
|----------------------|------------------------------------------------------------------------------|
| `ip_server`          | Dirección IP del servidor inspeccionado                                      |
| `port`               | Puerto utilizado                                                             |
| `connect_server`     | `TRUE` si la conexión fue exitosa                                            |
| `tls_enabled`        | `TRUE` si el servidor respondió con capa TLS                                 |
| `tls_version`        | Versión de protocolo TLS negociada                                           |
| `cipher`             | Cipher suite utilizado en la conexión TLS                                    |
| `issuer`             | Campo `Issuer` del certificado X.509                                         |
| `subject`            | Campo `Subject` del certificado                                              |
| `key_usage`          | Uso de clave (digitalSignature, keyEncipherment, etc.)                       |
| `extended_key_usage` | Usos extendidos (serverAuth, clientAuth, etc.)                               |
| `alternative_name`   | SAN (Subject Alternative Name), típicamente DNS                              |
| `basic_constraints`  | Indica si el certificado es CA o no                                          |
| `cert_type`          | Tipo de certificado (`RootCA`, `IntermediateCA-Level0`, `EndEntityCertificate`) |
| `date_before`        | Fecha de inicio de validez del certificado                                   |
| `date_after`         | Fecha de expiración del certificado                                          |
| `path`               | Ruta al archivo si aplica                                                    |
| `is_file`            | `TRUE` si se analizó un archivo `.crt`                                       |
| `certificate`        | Certificado X.509 completo en texto                                          |
| `openssl_output`     | Salida de depuración del comando `openssl s_client`                          |





---

### 🚀 **Uso**

La función puede recibir una IP con puerto, una lista separada por comas, o una ruta a un certificado `.crt`. Si se llama sin argumentos, se intenta descubrir valores por defecto.

#### ✅ **Ejemplos de llamada**

```sql
-- Inspeccionar conexión TLS a un servidor PostgreSQL
SELECT * FROM pgtlsinfo('192.168.1.100:5432');

-- Consultar múltiples servidores separados por coma
SELECT * FROM pgtlsinfo('127.0.0.1:5411,127.0.0.1:5414,127.0.0.1:5416');

-- Llamada sin parámetros (usar configuración interna o localhost)
SELECT * FROM pgtlsinfo();

-- Analizar certificados individuales desde disco
SELECT * FROM pgtlsinfo('/ruta/a/star_certificado.crt');
SELECT * FROM pgtlsinfo('/ruta/a/ca_certificado.crt');
SELECT * FROM pgtlsinfo('/ruta/a/root_certificado.crt');
```

---
