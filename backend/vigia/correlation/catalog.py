"""Vulnerability catalogue: taxonomy, scoring defaults and remediation for every finding category.

OWASP Top 10:2025 ids (A01 Broken Access Control … A10 Mishandling of Exceptional Conditions), OWASP API
Security Top 10:2023 (API1…API10), CWE, MITRE ATT&CK (Enterprise) technique, default CVSS 3.1 vector
(the contextual worst case for an internet-facing app; modules may override with a measured vector),
ASVS 5.0 / WSTG references and remediation guidance.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from vigia.core.findings import FindingDraft
from vigia.correlation import cvss

ASVS = "https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en"
WSTG = "https://owasp.org/www-project-web-security-testing-guide/stable/"
CWE = "https://cwe.mitre.org/data/definitions/{}.html"


@dataclass(frozen=True)
class Entry:
    key: str
    name: str
    cwe: str | None
    owasp: tuple[str, ...]
    vector: str | None
    attack: str | None
    impact: str
    fix: str
    refs: tuple[str, ...] = field(default_factory=tuple)
    severity: str | None = None  # used when there is no vector (informational / config hygiene)


def _v(av="N", ac="L", pr="N", ui="N", s="U", c="N", i="N", a="N") -> str:  # noqa: PLR0913
    return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"


_E: list[Entry] = [
    # ----------------------------------------------------------------- M10 configuration / headers
    Entry("missing_hsts", "HSTS ausente", "319", ("A02:2025", "A04:2025"), _v(ac="H", ui="R", c="L", i="L"), "T1557",
          "Un atacante en la red puede degradar la conexión a HTTP (SSL stripping) y robar sesiones.",
          "Envía `Strict-Transport-Security: max-age=31536000; includeSubDomains` en todas las respuestas HTTPS.",
          (f"{WSTG}4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security",)),
    Entry("missing_csp", "Content-Security-Policy ausente", "1021", ("A02:2025",), None, "T1189",
          "Sin CSP, cualquier XSS ejecuta código sin restricciones y no hay defensa en profundidad.",
          "Define una CSP restrictiva (default-src 'self'; script-src con nonces o hashes; object-src 'none'; "
          "base-uri 'none'; frame-ancestors).", (f"{ASVS}/0x12-V3-Web-Frontend-Security.md",), severity="low"),
    Entry("weak_csp", "Content-Security-Policy débil", "1021", ("A02:2025",), None, "T1189",
          "La política permite orígenes o directivas ('unsafe-inline', 'unsafe-eval', comodines) que anulan su protección frente a XSS.",
          "Elimina 'unsafe-inline'/'unsafe-eval' y comodines; usa nonces o hashes y 'strict-dynamic'.",
          ("https://csp-evaluator.withgoogle.com/",), severity="low"),
    Entry("clickjacking", "Protección contra clickjacking ausente", "1021", ("A02:2025",), _v(ui="R", i="L"), "T1185",
          "La página puede incrustarse en un iframe de un tercero y engañar al usuario para que haga clic en acciones sensibles.",
          "Añade `Content-Security-Policy: frame-ancestors 'self'` (y `X-Frame-Options: DENY` para navegadores antiguos)."),
    Entry("missing_xcto", "X-Content-Type-Options ausente", "693", ("A02:2025",), None, None,
          "El navegador puede interpretar contenido con un tipo distinto (MIME sniffing).",
          "Envía `X-Content-Type-Options: nosniff`.", severity="info"),
    Entry("missing_referrer_policy", "Referrer-Policy ausente", "200", ("A02:2025",), None, None,
          "URLs con tokens o datos pueden filtrarse a terceros en la cabecera Referer.",
          "Envía `Referrer-Policy: strict-origin-when-cross-origin` o `no-referrer`.", severity="info"),
    Entry("missing_permissions_policy", "Permissions-Policy ausente", "693", ("A02:2025",), None, None,
          "No se restringen APIs del navegador (cámara, micrófono, geolocalización) para contenido incrustado.",
          "Define `Permissions-Policy` desactivando las funciones que la aplicación no usa.", severity="info"),
    Entry("insecure_cookie", "Cookie de sesión sin atributos de seguridad", "614", ("A07:2025", "A02:2025"),
          _v(ac="H", ui="R", c="L", i="L"), "T1539",
          "Cookies sin Secure/HttpOnly/SameSite pueden robarse por red, por XSS o usarse en CSRF.",
          "Marca las cookies de sesión con `Secure; HttpOnly; SameSite=Lax` (o Strict) y usa el prefijo `__Host-`.",
          (f"{ASVS}/0x16-V7-Session-Management.md",)),
    Entry("cors_misconfig", "CORS permisivo", "942", ("A02:2025", "A01:2025", "API8:2023"), _v(ui="R", c="H"), "T1557",
          "Un sitio malicioso puede leer respuestas autenticadas de la API desde el navegador de la víctima.",
          "Valida `Origin` contra una lista blanca exacta; nunca reflejes orígenes arbitrarios ni `null` con credenciales.",
          (f"{WSTG}4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing",)),
    Entry("cache_sensitive", "Respuesta sensible almacenable en caché", "525", ("A02:2025",), None, None,
          "Datos personales o de sesión pueden quedar en cachés compartidas o del navegador.",
          "Envía `Cache-Control: no-store` en respuestas autenticadas o con datos personales.", severity="low"),
    Entry("version_disclosure", "Divulgación de versión del software", "200", ("A02:2025",), None, "T1592",
          "Facilita al atacante buscar exploits para la versión exacta.",
          "Oculta versiones en cabeceras (Server, X-Powered-By, X-AspNet-Version) y páginas de error.", severity="info"),
    Entry("error_disclosure", "Mensajes de error con información interna", "209", ("A02:2025", "A10:2025"),
          _v(c="L"), "T1592",
          "Trazas, rutas internas o consultas SQL en errores revelan la estructura interna y ayudan a explotar otros fallos.",
          "Captura las excepciones, devuelve mensajes genéricos y registra el detalle solo en el servidor.",
          (f"{ASVS}/0x25-V16-Security-Logging-and-Error-Handling.md",)),
    Entry("no_https", "Servicio accesible por HTTP sin redirección a HTTPS", "319", ("A04:2025",), _v(ac="H", c="L", i="L"),
          "T1040", "Credenciales y sesiones viajan en claro.", "Redirige todo el tráfico HTTP a HTTPS (301) y activa HSTS."),
    Entry("directory_listing", "Listado de directorios habilitado", "548", ("A02:2025",), _v(c="L"), "T1083",
          "Expone ficheros no enlazados (backups, configuraciones).", "Desactiva el autoindex del servidor web."),
    Entry("dangerous_methods", "Métodos HTTP peligrosos habilitados", "749", ("A02:2025", "API8:2023"), _v(c="L", i="L"),
          "T1190", "TRACE permite XST; PUT/DELETE/WebDAV sin control pueden permitir modificar contenido.",
          "Limita los métodos permitidos a los que la aplicación usa realmente."),
    Entry("mixed_content", "Contenido mixto (HTTP en página HTTPS)", "319", ("A04:2025",), None, "T1557",
          "Recursos cargados por HTTP pueden ser modificados en tránsito.", "Carga todos los recursos por HTTPS.",
          severity="low"),
    # ----------------------------------------------------------------- M07 exposure
    Entry("exposed_env", "Fichero .env expuesto", "538", ("A02:2025",), _v(c="H", i="H", a="H"), "T1552.001",
          "Contiene secretos (BD, API keys, claves de firma) que permiten comprometer la aplicación y servicios conectados.",
          "Elimina el fichero del docroot, bloquea dotfiles en el servidor web y ROTA todos los secretos expuestos."),
    Entry("exposed_git", "Repositorio .git expuesto", "527", ("A02:2025",), _v(c="H"), "T1213",
          "Permite reconstruir el código fuente y su historial, incluidos secretos borrados.",
          "Bloquea `/.git` en el servidor web y no despliegues el directorio del repositorio; revisa el historial en busca de secretos."),
    Entry("exposed_vcs", "Metadatos de control de versiones expuestos", "527", ("A02:2025",), _v(c="L"), "T1213",
          "Revela estructura de ficheros y a veces código.", "Excluye .svn/.hg/.bzr/.DS_Store del despliegue."),
    Entry("exposed_backup", "Copia de seguridad o fichero temporal expuesto", "530", ("A02:2025",), _v(c="H"), "T1213",
          "Backups de código o datos descargables públicamente.", "Elimina backups del docroot y guárdalos fuera del servidor web."),
    Entry("exposed_db_dump", "Volcado de base de datos expuesto", "530", ("A02:2025",), _v(c="H", i="L"), "T1213",
          "Datos (posiblemente personales y credenciales) descargables públicamente.",
          "Retira el fichero, evalúa la brecha de datos y notifica según la normativa aplicable."),
    Entry("exposed_config", "Fichero de configuración expuesto", "538", ("A02:2025",), _v(c="H"), "T1552.001",
          "Configuraciones con rutas, hosts internos o credenciales.", "Retira el fichero del docroot y rota los secretos que contenga."),
    Entry("exposed_log", "Fichero de log expuesto", "532", ("A09:2025", "A02:2025"), _v(c="L"), "T1213",
          "Los logs pueden contener datos personales, tokens o trazas internas.", "Mueve los logs fuera del docroot."),
    Entry("exposed_sourcemap", "Source map público", "540", ("A02:2025",), None, "T1592",
          "Permite reconstruir el código fuente original del frontend (comentarios, rutas internas, lógica).",
          "No publiques `.map` en producción o restringe su acceso.", severity="low"),
    Entry("exposed_private_key", "Clave privada expuesta", "321", ("A04:2025",), _v(c="H", i="H"), "T1552.004",
          "Permite suplantar el servidor, descifrar tráfico o firmar artefactos.", "Revoca y reemplaza la clave inmediatamente."),
    Entry("exposed_debug", "Endpoint de depuración o diagnóstico expuesto", "489", ("A02:2025",), _v(c="H", i="L"), "T1190",
          "phpinfo, Actuator, consolas de depuración o perfiles exponen configuración y a veces permiten ejecutar acciones.",
          "Desactiva los endpoints de depuración en producción o protégelos con autenticación y red interna."),
    Entry("exposed_admin", "Panel de administración accesible públicamente", "1188", ("A01:2025", "A07:2025"), None, "T1133",
          "Superficie de ataque para fuerza bruta y explotación de vulnerabilidades del panel.",
          "Restringe el acceso por red (VPN/IP) y exige MFA.", severity="low"),
    Entry("exposed_dev_env", "Entorno de desarrollo o staging expuesto", "1188", ("A02:2025",), None, "T1190",
          "Los entornos de desarrollo suelen tener depuración activa, datos reales y controles relajados.",
          "Protege los entornos no productivos con autenticación y restricción por red.", severity="medium"),
    Entry("exposed_api_docs", "Documentación de API (Swagger/OpenAPI) expuesta", "1059", ("API9:2023", "A02:2025"), None,
          "T1592", "Facilita el inventario completo de la API, incluidos endpoints internos.",
          "Publica la documentación solo en entornos internos o tras autenticación.", severity="low"),
    Entry("exposed_internal_doc", "Documentación interna expuesta", "200", ("A02:2025",), _v(c="L"), "T1213",
          "Documentos internos con arquitectura, credenciales o datos.", "Retira los documentos del servidor público."),
    # ----------------------------------------------------------------- recon / components
    Entry("outdated_component", "Componente con vulnerabilidades conocidas", "1104", ("A03:2025",), _v(c="H", i="H", a="H"),
          "T1190", "Versiones con CVE públicos pueden ser explotadas con exploits disponibles.",
          "Actualiza el componente a una versión corregida y suscríbete a sus avisos de seguridad."),
    Entry("tech_fingerprint", "Tecnología identificada", None, (), None, None, "Información de inventario.",
          "Mantén el inventario actualizado.", severity="info"),
    Entry("dns_email_auth", "Protección de correo (SPF/DMARC) ausente o débil", "290", ("A02:2025",), None, "T1566",
          "Permite suplantar el dominio en correos de phishing.", "Publica SPF estricto (-all) y DMARC con p=quarantine o reject.",
          severity="low"),
    Entry("dns_zone_transfer", "Transferencia de zona DNS (AXFR) permitida", "200", ("A02:2025",), _v(c="L"), "T1590.002",
          "Revela todos los registros de la zona, incluidos hosts internos.", "Restringe AXFR a los servidores secundarios autorizados."),
    Entry("subdomain_dangling", "Registro DNS apuntando a recurso inexistente", "350", ("A02:2025",), _v(ui="R", c="L", i="L"),
          "T1584.001", "Un CNAME a un servicio eliminado puede ser reclamado por un tercero (subdomain takeover).",
          "Elimina los registros DNS obsoletos."),
    # ----------------------------------------------------------------- TLS
    Entry("tls_old_protocol", "Protocolo TLS obsoleto habilitado", "327", ("A04:2025",), _v(ac="H", c="L"), "T1557",
          "SSLv3/TLS 1.0/1.1 tienen debilidades criptográficas conocidas (POODLE, BEAST) y están prohibidos por RFC 8996.",
          "Habilita solo TLS 1.2 y 1.3.", (f"{ASVS}/0x21-V12-Secure-Communication.md",)),
    Entry("tls_weak_cipher", "Suites de cifrado débiles", "326", ("A04:2025",), _v(ac="H", c="L"), "T1557",
          "Cifrados sin secreto perfecto hacia adelante, RC4, 3DES, NULL o EXPORT debilitan la confidencialidad.",
          "Configura solo suites AEAD con ECDHE (perfil 'intermediate' de Mozilla)."),
    Entry("cert_invalid", "Certificado TLS no válido", "295", ("A04:2025", "A07:2025"), _v(ac="H", ui="R", c="L", i="L"),
          "T1557", "Certificados caducados, autofirmados o con nombre incorrecto acostumbran a los usuarios a ignorar avisos y permiten MITM.",
          "Usa un certificado de una CA pública válido para todos los nombres servidos y renuévalo automáticamente."),
    Entry("cert_expiring", "Certificado TLS próximo a caducar", "298", ("A02:2025",), None, None,
          "La caducidad provocará interrupción del servicio o advertencias.", "Automatiza la renovación (ACME).", severity="low"),
    # ----------------------------------------------------------------- M06 infrastructure
    Entry("exposed_database", "Base de datos expuesta a Internet", "668", ("A02:2025",), _v(c="H", i="H", a="H"), "T1190",
          "Motores de BD accesibles públicamente son objetivo de fuerza bruta, explotación y ransomware.",
          "Restringe el puerto a redes privadas, exige autenticación fuerte y TLS."),
    Entry("db_no_auth", "Servicio de datos sin autenticación", "306", ("A07:2025", "A01:2025"), _v(c="H", i="H", a="H"), "T1190",
          "Redis/MongoDB/Elasticsearch/Memcached accesibles sin credenciales permiten leer y modificar todos los datos.",
          "Activa la autenticación, enlaza el servicio a interfaces privadas y aplica firewall."),
    Entry("exposed_container_api", "API de contenedores/orquestador expuesta", "306", ("A01:2025", "A02:2025"),
          _v(s="C", c="H", i="H", a="H"), "T1610",
          "Docker API, kubelet o etcd accesibles sin autenticación permiten ejecutar contenedores y tomar el control del host.",
          "Nunca expongas estos puertos; exige mTLS y RBAC."),
    Entry("exposed_remote_admin", "Servicio de administración remota expuesto", "1188", ("A02:2025", "A07:2025"), None, "T1133",
          "SSH/RDP/VNC/Telnet expuestos son objetivo constante de fuerza bruta.",
          "Restringe el acceso por VPN o lista de IPs y exige autenticación por clave/MFA.", severity="low"),
    Entry("cleartext_service", "Servicio sin cifrado (Telnet/FTP)", "319", ("A04:2025",), _v(ac="H", c="H"), "T1040",
          "Credenciales y datos viajan en claro.", "Sustituye por SSH/SFTP o protocolos con TLS."),
    Entry("ftp_anonymous", "FTP con acceso anónimo", "284", ("A01:2025",), _v(c="L"), "T1078.001",
          "Cualquiera puede listar y descargar ficheros.", "Desactiva el acceso anónimo."),
    Entry("smb_exposed", "SMB expuesto a Internet", "668", ("A02:2025",), _v(ac="H", c="H", i="H", a="H"), "T1210",
          "SMB público ha sido vector de gusanos (EternalBlue/WannaCry).", "Bloquea 139/445 en el perímetro."),
    Entry("unnecessary_service", "Servicio de red innecesario expuesto", "1327", ("A02:2025",), None, "T1046",
          "Cada servicio expuesto amplía la superficie de ataque.", "Cierra los puertos que no sean necesarios.", severity="low"),
    Entry("service_version_disclosure", "Banner de servicio con versión", "200", ("A02:2025",), None, "T1592",
          "Facilita la búsqueda de exploits.", "Oculta la versión en los banners.", severity="info"),
    # ----------------------------------------------------------------- M03 injection
    Entry("sqli", "Inyección SQL", "89", ("A05:2025",), _v(c="H", i="H", a="H"), "T1190",
          "Permite leer o modificar la base de datos y, según el motor, ejecutar comandos.",
          "Usa consultas parametrizadas u ORM sin concatenación; valida tipos; mínimo privilegio en la cuenta de BD.",
          (f"{WSTG}4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection",
           f"{ASVS}/0x10-V1-Encoding-and-Sanitization.md")),
    Entry("nosqli", "Inyección NoSQL", "943", ("A05:2025",), _v(c="H", i="H"), "T1190",
          "Operadores inyectados ($ne, $gt, $where) pueden saltarse autenticación o filtrar datos.",
          "Valida tipos estrictamente (rechaza objetos donde se esperan cadenas) y desactiva $where/JS en el servidor."),
    Entry("cmdi", "Inyección de comandos del sistema operativo", "78", ("A05:2025",), _v(c="H", i="H", a="H"), "T1059",
          "Ejecución remota de comandos en el servidor (RCE).",
          "No invoques shells con datos del usuario; usa APIs con lista de argumentos y listas blancas."),
    Entry("ldapi", "Inyección LDAP", "90", ("A05:2025",), _v(c="H", i="L"), "T1190",
          "Puede alterar consultas al directorio (bypass de autenticación, enumeración).", "Escapa los valores según RFC 4515 y usa APIs parametrizadas."),
    Entry("xpathi", "Inyección XPath", "643", ("A05:2025",), _v(c="H"), "T1190",
          "Permite alterar consultas XPath y leer el documento completo.", "Usa consultas XPath parametrizadas o precompiladas."),
    Entry("ssti", "Inyección de plantillas en servidor (SSTI)", "1336", ("A05:2025",), _v(c="H", i="H", a="H"), "T1190",
          "Los motores de plantillas suelen permitir ejecución de código en el servidor.",
          "No construyas plantillas con datos del usuario; pásalos como variables de contexto y usa entornos sandbox."),
    Entry("xss_reflected", "Cross-Site Scripting reflejado", "79", ("A05:2025",), _v(ui="R", s="C", c="L", i="L"), "T1189",
          "Ejecución de JavaScript en el navegador de la víctima: robo de sesión, acciones en su nombre.",
          "Codifica la salida según el contexto (HTML, atributo, JS, URL), usa plantillas con autoescape y CSP.",
          (f"{WSTG}4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting",)),
    Entry("xss_stored", "Cross-Site Scripting almacenado", "79", ("A05:2025",), _v(pr="L", ui="R", s="C", c="H", i="L"), "T1189",
          "El script persiste y se ejecuta en el navegador de todos los usuarios que ven el contenido.",
          "Codifica en la salida, sanea HTML enriquecido con una biblioteca de lista blanca y aplica CSP."),
    Entry("xss_dom", "Cross-Site Scripting basado en DOM", "79", ("A05:2025",), _v(ui="R", s="C", c="L", i="L"), "T1189",
          "Datos controlables (location, hash, postMessage) llegan a sumideros peligrosos del DOM.",
          "Usa textContent en lugar de innerHTML, Trusted Types y evita eval/Function con datos externos."),
    Entry("html_injection", "Inyección de HTML", "80", ("A05:2025",), _v(ui="R", i="L"), "T1189",
          "Permite insertar contenido falso (phishing) en páginas legítimas.", "Codifica la salida HTML."),
    Entry("crlf_injection", "Inyección CRLF / de cabeceras", "113", ("A05:2025",), _v(ui="R", c="L", i="L"), "T1190",
          "Permite inyectar cabeceras o dividir respuestas (fijación de sesión, XSS, envenenamiento de caché).",
          "Rechaza \\r y \\n en valores usados en cabeceras; usa las APIs del framework."),
    Entry("path_traversal", "Path traversal", "22", ("A01:2025",), _v(c="H"), "T1083",
          "Lectura de ficheros arbitrarios del servidor (configuraciones, claves).",
          "Resuelve la ruta canónica y verifica que está dentro del directorio permitido; usa identificadores en lugar de rutas."),
    Entry("open_redirect", "Redirección abierta", "601", ("A01:2025",), _v(ui="R", c="L", i="L"), "T1566.002",
          "Facilita phishing creíble y robo de tokens OAuth.", "Valida destinos contra una lista blanca o usa rutas relativas."),
    Entry("ssrf", "Server-Side Request Forgery (SSRF)", "918", ("A01:2025", "API7:2023"), _v(s="C", c="H", i="L"), "T1190",
          "El servidor puede ser usado para acceder a servicios internos o metadatos cloud.",
          "Valida destinos con lista blanca, bloquea rangos internos y metadatos tras resolver DNS, y no sigas redirecciones."),
    # ----------------------------------------------------------------- M02 API
    Entry("api_bola", "Autorización a nivel de objeto rota (BOLA/IDOR)", "639", ("API1:2023", "A01:2025"), _v(pr="L", c="H", i="L"),
          "T1190", "Un usuario accede a objetos de otros usuarios cambiando el identificador.",
          "Comprueba en el servidor que el objeto pertenece al usuario autenticado en cada acceso; usa identificadores no predecibles como defensa adicional."),
    Entry("api_bfla", "Autorización a nivel de función rota (BFLA)", "285", ("API5:2023", "A01:2025"), _v(pr="L", c="H", i="H"),
          "T1078", "Usuarios sin privilegios ejecutan funciones administrativas.",
          "Aplica control de acceso por rol en el servidor en cada endpoint, denegando por defecto."),
    Entry("api_auth_missing", "Endpoint sensible sin autenticación", "306", ("API2:2023", "A07:2025"), _v(c="H", i="L"), "T1190",
          "Funcionalidad o datos que deberían estar protegidos son accesibles anónimamente.", "Exige autenticación por defecto en todos los endpoints."),
    Entry("api_mass_assignment", "Asignación masiva (mass assignment)", "915", ("API3:2023", "A01:2025"), _v(pr="L", i="H"),
          "T1190", "El cliente puede modificar propiedades que no debería (rol, saldo, propietario).",
          "Usa DTOs con lista blanca de campos escribibles; nunca enlaces el cuerpo directamente al modelo."),
    Entry("api_excessive_data", "Exposición excesiva de datos", "213", ("API3:2023", "A01:2025"), _v(pr="L", c="L"), "T1213",
          "La API devuelve propiedades sensibles que el cliente no necesita.", "Define esquemas de respuesta explícitos y filtra en el servidor."),
    Entry("api_no_rate_limit", "Ausencia de limitación de peticiones", "770", ("API4:2023", "A06:2025"), _v(a="L"), "T1110",
          "Permite fuerza bruta, enumeración y abuso de recursos.",
          "Aplica rate limiting por usuario/IP y por endpoint sensible (login, OTP, recuperación de contraseña)."),
    Entry("api_jwt_weak", "JWT con configuración insegura", "347", ("API2:2023", "A04:2025", "A07:2025"), _v(c="H", i="H"),
          "T1550.001", "Tokens sin firma, con secreto débil o sin caducidad permiten falsificar o reutilizar sesiones.",
          "Fija el algoritmo en el servidor, usa secretos de ≥256 bits o claves asimétricas, y exige exp/iss/aud."),
    Entry("api_jwt_sensitive", "Datos sensibles en el payload del JWT", "315", ("API3:2023", "A04:2025"), None, "T1552",
          "El payload de un JWT solo está codificado, no cifrado.", "No incluyas datos sensibles en el JWT.", severity="low"),
    Entry("api_inventory", "Gestión de inventario de API deficiente", "1059", ("API9:2023",), None, "T1190",
          "Versiones antiguas, endpoints de depuración o no documentados siguen accesibles.",
          "Mantén un inventario, retira versiones obsoletas y aplica los mismos controles a todas.", severity="low"),
    Entry("graphql_introspection", "Introspección GraphQL habilitada", "200", ("API8:2023", "A02:2025"), None, "T1592",
          "Expone el esquema completo, incluidas mutaciones internas.", "Desactiva la introspección en producción.", severity="low"),
    Entry("api_verbose_errors", "Errores detallados en la API", "209", ("API8:2023", "A10:2025"), _v(c="L"), "T1592",
          "La API devuelve trazas o detalles internos.", "Devuelve errores genéricos con un identificador de correlación."),
    Entry("oauth_misconfig", "Configuración OAuth 2.0 insegura", "601", ("API2:2023", "A07:2025"), _v(ui="R", c="H"), "T1550.001",
          "redirect_uri sin validar, ausencia de state/PKCE o flujos implícitos permiten robar códigos o tokens.",
          "Valida redirect_uri exacto, exige PKCE y state, y no uses el flujo implícito."),
    Entry("csrf", "Cross-Site Request Forgery", "352", ("A01:2025",), _v(ui="R", i="H"), "T1185",
          "Un sitio externo puede provocar acciones en nombre del usuario autenticado.",
          "Usa tokens anti-CSRF o cookies SameSite=Lax/Strict y verifica Origin en peticiones que cambian estado."),
    Entry("auth_weakness", "Debilidad en la autenticación", "287", ("A07:2025",), _v(c="L", i="L"), "T1110",
          "Mensajes que revelan usuarios válidos, ausencia de bloqueo o formularios por HTTP facilitan el acceso no autorizado.",
          "Mensajes genéricos, bloqueo progresivo, MFA y transporte cifrado."),
    # ----------------------------------------------------------------- M04 frontend
    Entry("js_secret", "Secreto o credencial en JavaScript servido", "798", ("A04:2025", "A02:2025"), _v(c="H", i="L"), "T1552.001",
          "Cualquier visitante puede extraer la credencial y usar el servicio asociado.",
          "Mueve la credencial al servidor (proxy) y rótala; usa claves públicas restringidas por dominio solo cuando el proveedor lo permita."),
    Entry("js_dom_sink", "Uso peligroso del DOM en JavaScript", "79", ("A05:2025",), None, "T1189",
          "innerHTML/document.write/eval con datos no confiables pueden derivar en DOM XSS.",
          "Usa textContent, APIs seguras y Trusted Types.", severity="low"),
    Entry("js_token_storage", "Tokens de sesión en almacenamiento del navegador", "922", ("A07:2025",), None, "T1539",
          "localStorage/sessionStorage son legibles por cualquier script: un XSS roba la sesión.",
          "Guarda la sesión en cookies HttpOnly; si usas tokens en memoria, minimiza su vida útil.", severity="low"),
    Entry("js_vulnerable_library", "Librería JavaScript vulnerable", "1104", ("A03:2025",), _v(ui="R", c="L", i="L"), "T1189",
          "Versiones con vulnerabilidades conocidas (XSS, prototype pollution).", "Actualiza la librería a una versión corregida."),
    Entry("js_internal_info", "Información interna en JavaScript", "200", ("A02:2025",), None, "T1592",
          "URLs internas, IPs privadas o rutas de administración reveladas en el código cliente.", "Elimina información interna del bundle.",
          severity="info"),
    Entry("js_client_auth", "Control de acceso implementado en el cliente", "602", ("A01:2025", "A06:2025"), None, "T1190",
          "Las comprobaciones de rol o autenticación en el navegador se pueden saltar.",
          "Aplica todas las comprobaciones de autorización en el servidor.", severity="low"),
    # ----------------------------------------------------------------- M05/M08 SAST
    Entry("sast_sqli", "Consulta SQL construida con datos externos", "89", ("A05:2025",), _v(c="H", i="H", a="H"), "T1190",
          "Posible inyección SQL.", "Usa consultas parametrizadas."),
    Entry("sast_cmdi", "Ejecución de comandos con datos externos", "78", ("A05:2025",), _v(c="H", i="H", a="H"), "T1059",
          "Posible inyección de comandos (RCE).", "Evita shells; usa listas de argumentos y validación estricta."),
    Entry("sast_code_injection", "Evaluación dinámica de código", "95", ("A05:2025",), _v(c="H", i="H", a="H"), "T1059",
          "eval/exec/Function con datos externos permite ejecutar código arbitrario.", "Elimina la evaluación dinámica; usa parsers seguros."),
    Entry("sast_deserialization", "Deserialización insegura", "502", ("A08:2025",), _v(c="H", i="H", a="H"), "T1190",
          "Deserializar datos no confiables (pickle, ObjectInputStream, unserialize, BinaryFormatter, YAML inseguro) puede ejecutar código.",
          "Usa formatos de solo datos (JSON) o deserializadores con lista blanca de tipos."),
    Entry("sast_xss", "Salida HTML sin codificar", "79", ("A05:2025",), _v(ui="R", s="C", c="L", i="L"), "T1189",
          "Posible XSS por desactivar el autoescape o insertar HTML crudo.", "Mantén el autoescape y no marques datos externos como seguros."),
    Entry("sast_path_traversal", "Acceso a ficheros con ruta controlable", "22", ("A01:2025",), _v(c="H"), "T1083",
          "Posible lectura/escritura de ficheros arbitrarios.", "Normaliza y valida la ruta contra un directorio base."),
    Entry("sast_ssrf", "Petición saliente con URL controlable", "918", ("A01:2025",), _v(s="C", c="H", i="L"), "T1190",
          "Posible SSRF.", "Valida destinos con lista blanca y bloquea redes internas."),
    Entry("sast_weak_crypto", "Criptografía débil", "327", ("A04:2025",), _v(ac="H", c="H"), "T1600",
          "MD5/SHA1/DES/RC4/ECB o claves cortas no protegen adecuadamente los datos.", "Usa AES-GCM, SHA-256+ y bibliotecas de alto nivel."),
    Entry("sast_weak_random", "Generador aleatorio no criptográfico para seguridad", "338", ("A04:2025",), _v(ac="H", c="L", i="L"),
          "T1600", "Tokens predecibles.", "Usa `secrets` / `crypto.randomBytes` / `SecureRandom`."),
    Entry("sast_password_storage", "Almacenamiento de contraseñas inseguro", "916", ("A04:2025", "A07:2025"), _v(ac="H", c="H"), "T1110.002",
          "Hashes rápidos o sin sal permiten crackear contraseñas filtradas.", "Usa argon2id, scrypt o bcrypt."),
    Entry("sast_hardcoded_secret", "Secreto en el código fuente", "798", ("A04:2025", "A07:2025"), _v(c="H", i="H"), "T1552.001",
          "Cualquiera con acceso al repositorio obtiene la credencial.", "Mueve el secreto a un gestor de secretos y rótalo."),
    Entry("sast_debug", "Modo depuración activado", "489", ("A02:2025",), _v(c="H", i="L"), "T1190",
          "Depuración en producción expone trazas, configuración o consolas interactivas.", "Desactiva la depuración en configuración de producción."),
    Entry("sast_csrf_disabled", "Protección CSRF desactivada", "352", ("A01:2025",), _v(ui="R", i="H"), "T1185",
          "Las acciones que cambian estado pueden ser forzadas desde otro sitio.", "Activa la protección CSRF del framework."),
    Entry("sast_tls_verify", "Verificación TLS desactivada", "295", ("A04:2025", "A07:2025"), _v(ac="H", c="H", i="H"), "T1557",
          "Las conexiones salientes aceptan cualquier certificado (MITM).", "No desactives la verificación de certificados."),
    Entry("sast_xxe", "Parser XML vulnerable a XXE", "611", ("A02:2025", "A05:2025"), _v(c="H", a="L"), "T1190",
          "Entidades externas permiten leer ficheros o SSRF.", "Desactiva DTD y entidades externas (defusedxml, FEATURE_SECURE_PROCESSING)."),
    Entry("sast_open_redirect", "Redirección con destino controlable", "601", ("A01:2025",), _v(ui="R", c="L", i="L"), "T1566.002",
          "Posible redirección abierta.", "Valida el destino contra una lista blanca."),
    Entry("sast_template_injection", "Plantilla construida con datos externos", "1336", ("A05:2025",), _v(c="H", i="H", a="H"), "T1190",
          "Posible SSTI.", "Renderiza plantillas fijas con variables de contexto."),
    Entry("sast_nosql", "Consulta NoSQL con datos externos", "943", ("A05:2025",), _v(c="H", i="H"), "T1190",
          "Posible inyección NoSQL.", "Valida tipos y evita $where."),
    Entry("sast_ldap", "Consulta LDAP construida con datos externos", "90", ("A05:2025",), _v(c="H", i="L"), "T1190",
          "Posible inyección LDAP.", "Escapa los filtros LDAP."),
    Entry("sast_cors_any", "CORS abierto en la configuración", "942", ("A02:2025",), _v(ui="R", c="H"), "T1557",
          "Cualquier origen puede leer respuestas (crítico si se permiten credenciales).", "Configura una lista blanca de orígenes."),
    Entry("sast_missing_auth", "Ruta sin control de autenticación aparente", "862", ("A01:2025", "API5:2023"), None, "T1190",
          "La ruta no muestra decoradores/middleware de autenticación; si gestiona datos o acciones sensibles, podría ser accesible anónimamente.",
          "Verifica y aplica autenticación/autorización explícita o deniega por defecto.", severity="low"),
    Entry("sast_jwt", "Uso inseguro de JWT en el código", "347", ("A04:2025", "A07:2025"), _v(c="H", i="H"), "T1550.001",
          "Verificación de firma desactivada o algoritmo 'none' permitido.", "Verifica siempre la firma con una lista fija de algoritmos."),
    Entry("sast_logging_sensitive", "Datos sensibles en logs", "532", ("A09:2025",), None, "T1552",
          "Contraseñas o tokens registrados en logs.", "No registres secretos; aplica redacción.", severity="low"),
    Entry("sast_exception_handling", "Manejo inseguro de excepciones", "755", ("A10:2025",), None, None,
          "Excepciones silenciadas o que fallan en abierto (fail-open) pueden saltarse controles de seguridad.",
          "Falla de forma segura (fail-closed) y registra el error.", severity="low"),
    Entry("sast_regex_dos", "Expresión regular vulnerable a ReDoS", "1333", ("A06:2025",), _v(ac="H", a="H"), "T1499",
          "Entradas manipuladas provocan backtracking catastrófico y denegación de servicio.", "Reescribe la regex sin cuantificadores anidados o limita la entrada."),
    Entry("sast_insecure_config", "Configuración insegura", "16", ("A02:2025",), None, None,
          "Parámetro de configuración con un valor inseguro.", "Aplica la configuración segura recomendada.", severity="low"),
    Entry("sast_generic", "Patrón de código inseguro", None, ("A06:2025",), None, None,
          "Patrón inseguro detectado por análisis estático.", "Revisa el fragmento y aplica la corrección indicada.", severity="low"),
    # ----------------------------------------------------------------- secrets / SCA / IaC
    Entry("secret_exposed", "Secreto expuesto en el repositorio", "798", ("A04:2025", "A07:2025"), _v(c="H", i="H"), "T1552.001",
          "Credenciales en el código o en el historial pueden ser usadas por cualquiera con acceso.",
          "Revoca y rota el secreto, elimínalo del historial (git filter-repo) y usa un gestor de secretos."),
    Entry("vulnerable_dependency", "Dependencia con vulnerabilidad conocida", "1395", ("A03:2025",), None, "T1195.001",
          "La dependencia tiene una vulnerabilidad publicada (CVE/GHSA).", "Actualiza a la versión corregida indicada.", severity="medium"),
    Entry("unpinned_dependency", "Dependencia sin versión fijada", "1357", ("A03:2025", "A08:2025"), None, "T1195.001",
          "Versiones flotantes permiten que una publicación maliciosa o defectuosa entre en el build.",
          "Fija versiones exactas y usa ficheros de bloqueo con hashes.", severity="low"),
    Entry("iac_container_root", "Contenedor ejecutado como root", "250", ("A02:2025",), None, "T1611",
          "Un compromiso de la aplicación da root dentro del contenedor y facilita el escape.", "Define USER no privilegiado.", severity="medium"),
    Entry("iac_privileged", "Contenedor privilegiado o con capacidades excesivas", "250", ("A02:2025",), _v(av="L", pr="L", s="C", c="H", i="H", a="H"),
          "T1611", "privileged/hostPID/hostNetwork/hostPath/docker.sock permiten tomar el control del host.",
          "Elimina privileged y capacidades; usa cap_drop: ALL, read_only y no-new-privileges."),
    Entry("iac_secret", "Secreto en fichero de infraestructura", "798", ("A04:2025",), _v(c="H", i="H"), "T1552.001",
          "Credenciales en Dockerfile/compose/manifiestos.", "Usa secrets del orquestador o variables inyectadas en tiempo de ejecución."),
    Entry("iac_insecure_config", "Configuración de infraestructura insegura", "16", ("A02:2025",), None, None,
          "Configuración de contenedores/orquestador que no sigue las buenas prácticas.", "Aplica la recomendación indicada.", severity="low"),
    Entry("iac_image_unpinned", "Imagen base sin versión fijada", "1357", ("A03:2025",), None, "T1195.002",
          "`latest` o etiquetas mutables cambian sin control.", "Fija la imagen por digest (@sha256:...).", severity="low"),
    # ----------------------------------------------------------------- correlation / generic external
    Entry("route_unprotected", "Ruta del código expuesta sin autenticación en el despliegue", "306", ("A01:2025", "API2:2023"),
          _v(c="H", i="L"), "T1190", "La ruta existe en el código sin control de acceso y responde en el despliegue sin credenciales.",
          "Añade autenticación/autorización a la ruta o retírala."),
    Entry("route_shadow", "Endpoint expuesto que no aparece en el código analizado", "1059", ("API9:2023",), None, "T1190",
          "Endpoints no inventariados (shadow API) suelen carecer de controles.", "Inventaria o retira el endpoint.", severity="low"),
    Entry("external_finding", "Hallazgo de herramienta externa", None, (), None, None,
          "Reportado por una herramienta externa; requiere validación.", "Consulta la referencia de la herramienta.", severity="low"),
]

CATALOG: dict[str, Entry] = {e.key: e for e in _E}


def entry(key: str) -> Entry:
    return CATALOG.get(key) or CATALOG["external_finding"]


def enrich(f: FindingDraft) -> FindingDraft:
    """Fill taxonomy/score/remediation defaults; severity follows the CVSS vector when there is one."""
    e = entry(f.category)
    if not f.cwe and e.cwe:
        f.cwe = f"CWE-{e.cwe}"
    if f.cwe and not f.cwe.startswith("CWE-"):
        f.cwe = f"CWE-{f.cwe}"
    if not f.owasp:
        f.owasp = list(e.owasp)
    if not f.impact:
        f.impact = e.impact
    if not f.recommendation:
        f.recommendation = e.fix
    if e.attack and not any(t.startswith("attack:") for t in f.tags):
        f.tags.append(f"attack:{e.attack}")
    refs = list(f.references)
    if f.cwe:
        refs.append(CWE.format(f.cwe.split("-")[-1]))
    refs.extend(e.refs)
    f.references = list(dict.fromkeys(refs))
    if f.cvss_vector is None and e.vector and f.severity != "info" and not f.keep_severity:
        f.cvss_vector = e.vector
    if f.cvss_vector:
        try:
            f.severity = cvss.severity(cvss.base_score(f.cvss_vector))
        except cvss.CvssError:
            f.cvss_vector = None
    elif e.severity and f.severity == "medium" and e.severity != "medium" and not f.keep_severity:
        # catalogue default severity for vector-less categories unless the module set something explicit
        f.severity = e.severity
    if not f.likelihood:
        f.likelihood = {"confirmed": "high", "likely": "medium", "suspected": "low"}.get(f.confidence, "low")
    return f


def score(f: FindingDraft) -> float | None:
    if not f.cvss_vector:
        return None
    try:
        return cvss.base_score(f.cvss_vector)
    except cvss.CvssError:
        return None
