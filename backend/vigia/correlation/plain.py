"""Plain-language (non-specialist) Spanish texts for every finding category.

The technical catalogue (``catalog.py``) keeps the precise names, CWE / OWASP / ATT&CK mapping, CVSS defaults and
remediation detail used by the advanced views. This module is the business-facing layer: for each category it gives a
short plain title, a one-or-two sentence summary, the possible consequence for the business or its users and a short
action, written in neutral Spanish for readers who are not security specialists. It feeds the main UI and the executive
report.

The module is pure data plus a few helpers: importing it has no side effects and adds no dependencies.
"""
from __future__ import annotations

PlainText = dict[str, str]  # keys: title, summary, impact, action

PLAIN: dict[str, PlainText] = {
    # ----------------------------------------------------------------------------- configuration / headers
    "missing_hsts": {
        "title": "El sitio no obliga a usar siempre una conexión cifrada",
        "summary": ("El sitio no indica a los navegadores que deben conectarse siempre de forma cifrada. Alguien en "
                    "la misma red (por ejemplo, una wifi pública) podría forzar una conexión sin cifrar e "
                    "interceptarla."),
        "impact": "Un atacante cercano podría robar sesiones abiertas y suplantar a los usuarios afectados.",
        "action": "Pide al equipo técnico que configure el sitio para exigir siempre conexiones cifradas.",
    },
    "missing_csp": {
        "title": "Falta una capa de protección contra código malicioso en las páginas",
        "summary": ("El sitio no declara qué fuentes de contenido son de confianza. Esta medida no corrige fallos "
                    "por sí sola, pero limita mucho el daño si alguien consigue inyectar código en una página."),
        "impact": ("Por sí solo el riesgo es bajo, pero si existe otro fallo de inyección sus consecuencias serán "
                   "mayores."),
        "action": ("Pide al equipo de desarrollo que defina una política que solo permita contenido del propio sitio "
                   "y de proveedores de confianza."),
    },
    "weak_csp": {
        "title": "La protección contra código malicioso en las páginas es demasiado permisiva",
        "summary": ("El sitio declara qué contenido es de confianza, pero con excepciones tan amplias que la "
                    "protección apenas tiene efecto frente a código inyectado."),
        "impact": "El riesgo directo es bajo, pero si existe un fallo de inyección esta protección no lo frenaría.",
        "action": ("Pide al equipo de desarrollo que elimine las excepciones amplias y autorice solo los recursos "
                   "necesarios."),
    },
    "clickjacking": {
        "title": "Otras webs pueden mostrar este sitio camuflado para engañar a los usuarios",
        "summary": ("Las páginas pueden incrustarse dentro de otra web. Un atacante podría superponer elementos "
                    "engañosos para que el usuario pulse, sin saberlo, botones de acciones sensibles."),
        "impact": "Los usuarios podrían realizar acciones no deseadas en su cuenta sin darse cuenta.",
        "action": "Pide al equipo técnico que impida que el sitio se muestre dentro de páginas de terceros.",
    },
    "missing_xcto": {
        "title": "El navegador podría interpretar archivos de un tipo distinto al previsto",
        "summary": ("Falta una indicación que impide al navegador adivinar el tipo de los archivos que recibe. En "
                    "casos concretos, un archivo podría tratarse como contenido ejecutable."),
        "impact": "El riesgo directo es bajo; es una medida de refuerzo recomendada.",
        "action": "Pide al equipo técnico que obligue al navegador a respetar el tipo declarado de cada archivo.",
    },
    "missing_referrer_policy": {
        "title": "Las direcciones visitadas pueden compartirse con sitios de terceros",
        "summary": ("Cuando un usuario pasa del sitio a otra web, el navegador puede enviar la dirección completa de "
                    "la página de origen. Si esa dirección contiene datos o códigos de acceso, llegarían a terceros."),
        "impact": ("El riesgo directo es bajo, salvo que las direcciones de las páginas contengan datos personales o "
                   "códigos de acceso."),
        "action": ("Pide al equipo técnico que limite la información de procedencia que el navegador comparte con "
                   "otros sitios."),
    },
    "missing_permissions_policy": {
        "title": "No se limitan funciones sensibles del navegador como cámara o ubicación",
        "summary": ("El sitio no restringe el uso de funciones del navegador como la cámara, el micrófono o la "
                    "ubicación por parte del contenido incrustado."),
        "impact": "El riesgo directo es bajo; es una medida de refuerzo recomendada.",
        "action": "Pide al equipo técnico que desactive las funciones del navegador que el sitio no utiliza.",
    },
    "insecure_cookie": {
        "title": "Las cookies de sesión no tienen las protecciones recomendadas",
        "summary": ("Las cookies que mantienen iniciada la sesión no tienen activadas las protecciones habituales. "
                    "Podrían enviarse sin cifrar, leerse desde código malicioso o usarse desde otros sitios."),
        "impact": "Un atacante podría robar o reutilizar la sesión de un usuario y actuar en su nombre.",
        "action": "Pide al equipo de desarrollo que active las protecciones de seguridad de las cookies de sesión.",
    },
    "cors_misconfig": {
        "title": "Otros sitios web pueden leer datos privados de los usuarios conectados",
        "summary": ("El servidor permite que páginas de otros orígenes lean sus respuestas. Una web maliciosa "
                    "visitada por un usuario con la sesión iniciada podría obtener sus datos sin que lo note."),
        "impact": "Exposición de datos personales o confidenciales de los usuarios que visiten una web maliciosa.",
        "action": "Pide al equipo de desarrollo que solo permita el acceso desde una lista cerrada de sitios propios.",
    },
    "cache_sensitive": {
        "title": "Páginas con datos privados pueden quedar guardadas en memorias temporales",
        "summary": ("Algunas respuestas con datos personales o de sesión no indican que no deben almacenarse. "
                    "Podrían quedar guardadas en el navegador o en sistemas intermedios compartidos."),
        "impact": "Otra persona que use el mismo equipo o red podría ver información privada de un usuario anterior.",
        "action": "Pide al equipo técnico que marque las páginas con datos personales para que nunca se almacenen.",
    },
    "version_disclosure": {
        "title": "El sitio revela qué versión exacta de software utiliza",
        "summary": ("El servidor muestra el nombre y la versión de los programas que usa. No es un fallo en sí "
                    "mismo, pero ayuda a un atacante a buscar debilidades conocidas de esa versión."),
        "impact": "El riesgo directo es bajo; solo facilita la preparación de otros ataques.",
        "action": "Pide al equipo técnico que oculte las versiones del software en las respuestas y páginas de error.",
    },
    "error_disclosure": {
        "title": "Los mensajes de error muestran información interna del sistema",
        "summary": ("Cuando algo falla, el sitio muestra detalles técnicos internos (rutas, consultas, trazas del "
                    "programa). Esa información ayuda a un atacante a entender el sistema y aprovechar otros fallos."),
        "impact": "Facilita ataques más dirigidos y puede revelar datos internos de la organización.",
        "action": ("Pide al equipo de desarrollo que muestre mensajes de error genéricos y guarde el detalle solo "
                   "internamente."),
    },
    "no_https": {
        "title": "El servicio puede usarse sin cifrado y la información viaja a la vista",
        "summary": ("El servicio responde por una conexión no cifrada y no redirige a la versión segura. Contraseñas "
                    "y sesiones pueden viajar a la vista de quien esté en la misma red."),
        "impact": "Robo de contraseñas o sesiones de usuarios conectados desde redes no confiables.",
        "action": "Pide al equipo técnico que redirija todo el tráfico a la versión cifrada y la haga obligatoria.",
    },
    "directory_listing": {
        "title": "Cualquiera puede ver la lista de archivos de algunas carpetas del servidor",
        "summary": ("El servidor muestra el contenido completo de algunas carpetas. Así pueden descubrirse archivos "
                    "que no estaban enlazados, como copias de seguridad o configuraciones."),
        "impact": "Posible exposición de archivos internos o confidenciales.",
        "action": "Pide al equipo técnico que desactive el listado automático de carpetas en el servidor web.",
    },
    "dangerous_methods": {
        "title": "El servidor acepta operaciones peligrosas que no necesita",
        "summary": ("El servidor admite tipos de petición poco habituales que pueden permitir modificar o borrar "
                    "contenido, o que facilitan el robo de información de sesión."),
        "impact": "Si no están controladas, alguien podría alterar el contenido del sitio o facilitar otros ataques.",
        "action": "Pide al equipo técnico que limite las operaciones aceptadas a las que la aplicación usa realmente.",
    },
    "mixed_content": {
        "title": "Páginas seguras cargan recursos por una conexión sin cifrar",
        "summary": ("Algunas páginas cifradas incluyen imágenes, código u otros recursos que se descargan sin "
                    "cifrar. Alguien en la red podría modificarlos por el camino."),
        "impact": "Un atacante en la red podría alterar lo que ven los usuarios; el riesgo suele ser bajo.",
        "action": ("Pide al equipo de desarrollo que cargue todos los recursos de las páginas mediante conexiones "
                   "cifradas."),
    },
    # -------------------------------------------------------------------------------------------- exposure
    "exposed_env": {
        "title": "Un archivo con contraseñas y claves del sistema es públicamente accesible",
        "summary": ("Se puede descargar desde Internet un archivo de configuración que suele contener contraseñas de "
                    "la base de datos, claves de servicios externos y otros secretos."),
        "impact": "Un atacante podría tomar el control de la aplicación y de los servicios conectados a ella.",
        "action": "Retira el archivo del servidor de inmediato y cambia todas las contraseñas y claves que contenía.",
    },
    "exposed_git": {
        "title": "El código fuente y su historial de cambios se pueden descargar",
        "summary": ("Está publicada la carpeta interna del control de versiones. Con ella se puede reconstruir el "
                    "código fuente completo, incluidas contraseñas que se borraron en el pasado."),
        "impact": "Exposición del código y de secretos que permiten ataques mucho más precisos.",
        "action": ("Pide al equipo técnico que bloquee el acceso a esa carpeta y revise el historial en busca de "
                   "contraseñas."),
    },
    "exposed_vcs": {
        "title": "Se publican archivos internos que revelan la estructura del proyecto",
        "summary": ("Hay archivos de control de versiones o del sistema operativo accesibles públicamente. Revelan "
                    "nombres de archivos y carpetas internos y, a veces, parte del código."),
        "impact": "Exposición limitada de información interna que facilita otros ataques.",
        "action": "Pide al equipo técnico que excluya estos archivos internos al publicar el sitio.",
    },
    "exposed_backup": {
        "title": "Hay copias de seguridad descargables públicamente",
        "summary": ("Se encontraron copias de seguridad o archivos temporales accesibles desde Internet. Pueden "
                    "contener código fuente o datos de la organización."),
        "impact": "Exposición de código o datos confidenciales a cualquier persona.",
        "action": "Retira las copias de seguridad del servidor público y guárdalas fuera del alcance de Internet.",
    },
    "exposed_db_dump": {
        "title": "Una copia de la base de datos se puede descargar desde Internet",
        "summary": ("Se encontró accesible públicamente una copia de la base de datos. Puede contener datos "
                    "personales, de clientes o contraseñas."),
        "impact": "Posible brecha de datos personales, con consecuencias legales y de reputación.",
        "action": ("Retira el archivo de inmediato, evalúa qué datos se expusieron y notifica la brecha si la "
                   "normativa lo exige."),
    },
    "exposed_config": {
        "title": "Un archivo de configuración interna es públicamente accesible",
        "summary": ("Se puede descargar un archivo de configuración que puede incluir direcciones de sistemas "
                    "internos, rutas o contraseñas."),
        "impact": ("Exposición de información interna y, si contiene contraseñas, acceso no autorizado a otros "
                   "sistemas."),
        "action": "Retira el archivo del servidor público y cambia cualquier contraseña o clave que contenga.",
    },
    "exposed_log": {
        "title": "Los registros de actividad del sistema son públicamente accesibles",
        "summary": ("Se pueden descargar archivos de registro de la aplicación. Suelen contener datos personales, "
                    "códigos de sesión o detalles técnicos internos."),
        "impact": "Exposición de datos personales o de sesión de los usuarios.",
        "action": "Pide al equipo técnico que mueva los registros a una ubicación no accesible desde Internet.",
    },
    "exposed_sourcemap": {
        "title": "Se puede reconstruir el código original de la parte visible del sitio",
        "summary": ("Se publican archivos auxiliares que permiten recuperar el código original de la interfaz, con "
                    "comentarios, rutas internas y lógica de funcionamiento."),
        "impact": "El riesgo directo es bajo, pero facilita encontrar otros fallos.",
        "action": "Pide al equipo de desarrollo que no publique estos archivos auxiliares en el sitio real.",
    },
    "exposed_private_key": {
        "title": "Una clave privada de seguridad está expuesta públicamente",
        "summary": ("Se encontró accesible una clave privada, que debería ser secreta. Con ella se puede suplantar "
                    "al servidor, descifrar comunicaciones o firmar contenido como si fuera legítimo."),
        "impact": "Suplantación de la organización e interceptación de comunicaciones confidenciales.",
        "action": "Revoca la clave y sustitúyela por una nueva de inmediato.",
    },
    "exposed_debug": {
        "title": "Herramientas internas de diagnóstico están abiertas en Internet",
        "summary": ("Hay páginas o consolas de diagnóstico accesibles públicamente. Muestran la configuración del "
                    "sistema y, en algunos casos, permiten ejecutar acciones."),
        "impact": "Exposición de la configuración interna y posible control parcial del sistema.",
        "action": ("Pide al equipo técnico que desactive estas herramientas en el sitio real o las restrinja a la "
                   "red interna."),
    },
    "exposed_admin": {
        "title": "El panel de administración es accesible desde cualquier lugar de Internet",
        "summary": ("La página de acceso a la administración está abierta a todo Internet. No es un fallo por sí "
                    "mismo, pero la convierte en objetivo de intentos masivos de adivinar contraseñas."),
        "impact": ("Si las contraseñas son débiles o el panel tiene fallos, alguien podría tomar el control de la "
                   "administración."),
        "action": "Restringe el acceso al panel a redes autorizadas y exige verificación en dos pasos.",
    },
    "exposed_dev_env": {
        "title": "Un entorno de pruebas o desarrollo es accesible desde Internet",
        "summary": ("Hay una versión de pruebas o desarrollo publicada. Estos entornos suelen tener menos "
                    "protecciones, herramientas de diagnóstico activas y, a veces, datos reales."),
        "impact": "Puede servir de puerta de entrada más fácil a datos o sistemas de la organización.",
        "action": "Protege los entornos de pruebas con contraseña y restringe su acceso a la red interna.",
    },
    "exposed_api_docs": {
        "title": "La documentación técnica de los servicios de la aplicación es pública",
        "summary": ("Está publicada la documentación que describe todas las funciones que ofrece la aplicación a "
                    "otros programas, incluidas algunas internas. Facilita a un atacante saber qué probar."),
        "impact": "El riesgo directo es bajo, pero ahorra trabajo a un atacante.",
        "action": "Publica esa documentación solo en entornos internos o tras iniciar sesión.",
    },
    "exposed_internal_doc": {
        "title": "Hay documentos internos publicados en el servidor",
        "summary": ("Se encontraron documentos internos accesibles públicamente que pueden describir la arquitectura "
                    "o incluir contraseñas o datos."),
        "impact": "Exposición de información interna o confidencial de la organización.",
        "action": "Retira los documentos internos del servidor público.",
    },
    # ---------------------------------------------------------------------------------- recon / components
    "outdated_component": {
        "title": "Se usa software con fallos de seguridad conocidos y públicos",
        "summary": ("Un componente del sistema tiene una versión con fallos de seguridad ya publicados. Para muchos "
                    "de ellos existen herramientas de ataque al alcance de cualquiera."),
        "impact": "Según el fallo, un atacante podría acceder a datos, alterarlos o detener el servicio.",
        "action": "Pide al equipo técnico que actualice el componente a una versión corregida.",
    },
    "tech_fingerprint": {
        "title": "Se identificó una tecnología utilizada por el sitio",
        "summary": "Se detectó qué tecnología o producto usa el sistema. Es información de inventario, no un fallo.",
        "impact": "El riesgo directo es bajo o nulo; sirve para mantener el inventario tecnológico.",
        "action": "Comprueba que la tecnología figura en el inventario y se mantiene actualizada.",
    },
    "dns_email_auth": {
        "title": "Se podrían enviar correos falsos en nombre del dominio de la organización",
        "summary": ("El dominio no tiene configuradas, o las tiene débiles, las protecciones que permiten a los "
                    "servidores de correo rechazar mensajes falsificados en su nombre."),
        "impact": "Facilita engaños por correo dirigidos a clientes y empleados, con daño a la reputación.",
        "action": ("Pide al equipo técnico que publique en modo estricto las políticas de autenticación de correo "
                   "del dominio."),
    },
    "dns_zone_transfer": {
        "title": "Cualquiera puede obtener el listado completo de sistemas del dominio",
        "summary": ("Los servidores de nombres del dominio entregan su listado completo a quien lo pida. Eso revela "
                    "nombres de sistemas, incluidos algunos internos."),
        "impact": ("Facilita a un atacante descubrir sistemas que no deberían conocerse; el impacto directo es "
                   "limitado."),
        "action": "Pide al equipo técnico que solo entregue ese listado a los servidores secundarios autorizados.",
    },
    "subdomain_dangling": {
        "title": "Un subdominio apunta a un servicio que ya no existe y podría ser usurpado",
        "summary": ("Un nombre del dominio sigue apuntando a un servicio externo que se eliminó. Un tercero podría "
                    "registrar ese servicio y publicar contenido bajo el nombre de la organización."),
        "impact": "Suplantación creíble de la organización, robo de datos de usuarios o daño a la reputación.",
        "action": "Pide al equipo técnico que elimine los registros del dominio que ya no se usan.",
    },
    # ---------------------------------------------------------------- encrypted connections / certificates
    "tls_old_protocol": {
        "title": "Se admiten versiones antiguas e inseguras del cifrado de las conexiones",
        "summary": ("El servidor acepta versiones antiguas del cifrado de las comunicaciones con debilidades "
                    "conocidas, que los estándares actuales ya prohíben."),
        "impact": ("En condiciones concretas se podría descifrar parte de la información; el riesgo práctico es "
                   "bajo, pero incumple los estándares actuales."),
        "action": "Pide al equipo técnico que permita solo las versiones modernas del cifrado.",
    },
    "tls_weak_cipher": {
        "title": "El cifrado de las comunicaciones admite métodos débiles",
        "summary": ("El servidor acepta algoritmos de cifrado antiguos o débiles que ofrecen menos protección de la "
                    "que hoy se considera adecuada."),
        "impact": ("En condiciones concretas la confidencialidad de las comunicaciones podría reducirse; el riesgo "
                   "práctico es bajo."),
        "action": "Pide al equipo técnico que configure solo los métodos de cifrado modernos recomendados.",
    },
    "cert_invalid": {
        "title": "El certificado de seguridad del sitio no es válido",
        "summary": ("El certificado que acredita la identidad del sitio está caducado, es autofirmado o no "
                    "corresponde al nombre del sitio. Los navegadores muestran avisos y los usuarios se acostumbran "
                    "a ignorarlos."),
        "impact": "Pérdida de confianza de los usuarios y mayor facilidad para interceptar o suplantar el sitio.",
        "action": "Instala un certificado válido de una autoridad reconocida y configura su renovación automática.",
    },
    "cert_expiring": {
        "title": "El certificado de seguridad del sitio caducará pronto",
        "summary": ("El certificado que acredita la identidad del sitio está cerca de su fecha de caducidad. Si no "
                    "se renueva, los navegadores mostrarán avisos o bloquearán el acceso."),
        "impact": ("El riesgo directo es bajo, pero si caduca provocará interrupciones del servicio y avisos a los "
                   "usuarios."),
        "action": "Renueva el certificado y automatiza su renovación.",
    },
    # -------------------------------------------------------------------------------------- infrastructure
    "exposed_database": {
        "title": "Una base de datos es accesible directamente desde Internet",
        "summary": ("El servicio de base de datos acepta conexiones desde cualquier lugar de Internet. Estos "
                    "servicios son objetivo habitual de intentos de acceso y de secuestro de datos."),
        "impact": "Riesgo de robo, alteración o secuestro de los datos almacenados.",
        "action": ("Pide al equipo de sistemas que limite la base de datos a la red interna y exija autenticación "
                   "fuerte."),
    },
    "db_no_auth": {
        "title": "Un almacén de datos se puede usar sin usuario ni contraseña",
        "summary": ("Un servicio de almacenamiento de datos acepta conexiones sin pedir credenciales. Cualquiera que "
                    "llegue a él puede leer y modificar todo su contenido."),
        "impact": "Robo, alteración o borrado de todos los datos de ese servicio.",
        "action": "Activa la autenticación del servicio y ciérralo al acceso desde Internet.",
    },
    "exposed_container_api": {
        "title": "Cualquiera podría tomar el control de los servidores de aplicaciones",
        "summary": ("El sistema que gestiona los entornos donde se ejecutan las aplicaciones es accesible sin "
                    "autenticación. Permite ejecutar programas en los servidores y tomar el control de las máquinas."),
        "impact": "Control total de los servidores afectados, con acceso a todos sus datos y servicios.",
        "action": "Cierra de inmediato el acceso público a estos servicios y exige autenticación y permisos por rol.",
    },
    "exposed_remote_admin": {
        "title": "Un acceso de administración remota está abierto a Internet",
        "summary": ("Hay servicios para administrar servidores a distancia accesibles desde cualquier lugar. No es "
                    "un fallo por sí mismo, pero reciben intentos constantes de adivinar contraseñas."),
        "impact": "Si alguna credencial es débil o se filtra, un atacante podría tomar el control del servidor.",
        "action": ("Restringe estos accesos a una red privada o a direcciones autorizadas y exige verificación en "
                   "dos pasos."),
    },
    "cleartext_service": {
        "title": "Un servicio transmite contraseñas y datos sin cifrar",
        "summary": ("Hay un servicio que usa un protocolo antiguo sin cifrado. Las contraseñas y los datos viajan a "
                    "la vista y pueden leerse en la red."),
        "impact": "Robo de contraseñas y de la información transmitida.",
        "action": "Sustituye el servicio por una alternativa cifrada.",
    },
    "ftp_anonymous": {
        "title": "Un servidor de archivos permite entrar sin usuario ni contraseña",
        "summary": ("El servicio de transferencia de archivos permite el acceso anónimo. Cualquiera puede ver la "
                    "lista de archivos y descargarlos."),
        "impact": "Exposición de los archivos almacenados en ese servidor.",
        "action": "Desactiva el acceso anónimo al servidor de archivos.",
    },
    "smb_exposed": {
        "title": "El servicio de carpetas compartidas de red está abierto a Internet",
        "summary": ("El servicio que se usa para compartir carpetas en las redes de oficina es accesible desde "
                    "Internet. Ha sido la vía de entrada de ataques masivos de secuestro de datos."),
        "impact": "Posible toma de control de equipos y propagación de programas de secuestro de datos.",
        "action": "Pide al equipo de sistemas que bloquee este servicio en el perímetro de la red.",
    },
    "unnecessary_service": {
        "title": "Hay servicios de red abiertos que no parecen necesarios",
        "summary": ("Se detectaron servicios accesibles desde Internet que no parecen imprescindibles. Cada servicio "
                    "abierto es una posible puerta de entrada adicional."),
        "impact": "El riesgo directo es bajo, pero aumenta las oportunidades de ataque.",
        "action": "Cierra los servicios y puertos que no sean necesarios.",
    },
    "service_version_disclosure": {
        "title": "Un servicio de red muestra públicamente su versión",
        "summary": ("Un servicio informa de su nombre y versión exacta al conectarse. No es un fallo en sí mismo, "
                    "pero facilita buscar debilidades conocidas."),
        "impact": "El riesgo directo es bajo; solo facilita la preparación de otros ataques.",
        "action": "Configura el servicio para que no muestre su versión.",
    },
    # ------------------------------------------------------------------------------------------- injection
    "sqli": {
        "title": "Un atacante podría leer o modificar la base de datos",
        "summary": ("Un dato enviado por el usuario se usa sin control en una consulta a la base de datos. "
                    "Manipulándolo, se pueden ejecutar consultas no previstas."),
        "impact": "Robo o alteración de los datos almacenados y, según el sistema, toma de control del servidor.",
        "action": "Pide al equipo de desarrollo que construya las consultas separando siempre los datos del usuario.",
    },
    "nosqli": {
        "title": "Un atacante podría saltarse controles o leer datos de la base de datos",
        "summary": ("Los datos enviados por el usuario pueden alterar las búsquedas en la base de datos. Así se "
                    "podría entrar sin la contraseña correcta u obtener datos que no corresponden."),
        "impact": "Acceso no autorizado a cuentas o exposición de datos almacenados.",
        "action": ("Pide al equipo de desarrollo que valide estrictamente el tipo y formato de los datos antes de "
                   "usarlos."),
    },
    "cmdi": {
        "title": "Un atacante podría ejecutar órdenes directamente en el servidor",
        "summary": ("Un dato enviado por el usuario llega sin control a una orden del sistema operativo del "
                    "servidor. Manipulándolo, se pueden ejecutar órdenes arbitrarias."),
        "impact": "Toma de control completa del servidor, con acceso a todos sus datos.",
        "action": "Pide al equipo de desarrollo que no pase datos del usuario a órdenes del sistema.",
    },
    "ldapi": {
        "title": "Se pueden manipular las consultas al directorio de usuarios",
        "summary": ("Los datos enviados por el usuario alteran las búsquedas en el directorio de usuarios de la "
                    "organización. Podría permitir entrar sin credenciales válidas o descubrir usuarios."),
        "impact": "Acceso no autorizado o exposición de información del directorio corporativo.",
        "action": "Pide al equipo de desarrollo que escape los datos antes de usarlos en búsquedas del directorio.",
    },
    "xpathi": {
        "title": "Se pueden manipular las búsquedas en documentos de datos de la aplicación",
        "summary": ("Los datos enviados por el usuario alteran las búsquedas que la aplicación hace en sus "
                    "documentos de datos, lo que permite leer el documento completo."),
        "impact": "Exposición de toda la información contenida en esos documentos.",
        "action": "Pide al equipo de desarrollo que use búsquedas predefinidas que separen los datos del usuario.",
    },
    "ssti": {
        "title": "Un atacante podría ejecutar código en el servidor a través de las plantillas",
        "summary": ("Los datos del usuario se incorporan a las plantillas con las que el servidor genera las "
                    "páginas. Muchos sistemas de plantillas permiten así ejecutar código en el servidor."),
        "impact": "Posible toma de control del servidor y acceso a sus datos.",
        "action": ("Pide al equipo de desarrollo que use plantillas fijas y pase los datos del usuario solo como "
                   "variables."),
    },
    "xss_reflected": {
        "title": "Se puede ejecutar código no autorizado en el navegador de los usuarios",
        "summary": ("La página devuelve sin filtrar datos recibidos en un enlace o formulario. Un atacante puede "
                    "preparar un enlace que, al abrirlo, ejecute código suyo en el navegador de la víctima."),
        "impact": "Robo de sesión y acciones en nombre de los usuarios que abran el enlace malicioso.",
        "action": "Pide al equipo de desarrollo que valide y escape los datos que se muestran en la página.",
    },
    "xss_stored": {
        "title": "Se puede guardar código malicioso que se ejecuta al ver ciertas páginas",
        "summary": ("Se puede guardar en el sitio contenido con código que después se ejecuta en el navegador de "
                    "cada usuario que lo ve, sin que tenga que hacer nada especial."),
        "impact": "Robo de sesiones y acciones en nombre de todos los usuarios que vean el contenido afectado.",
        "action": "Pide al equipo de desarrollo que escape los datos al mostrarlos y filtre el contenido con formato.",
    },
    "xss_dom": {
        "title": "Un enlace manipulado puede ejecutar código en el navegador de los usuarios",
        "summary": ("El código que se ejecuta en el navegador usa de forma insegura datos que un atacante puede "
                    "controlar, como partes del enlace. Un enlace preparado podría ejecutar código en el navegador "
                    "de la víctima."),
        "impact": "Robo de sesión y acciones en nombre de los usuarios que abran un enlace malicioso.",
        "action": ("Pide al equipo de desarrollo que trate siempre como texto los datos externos que inserta en la "
                   "página."),
    },
    "html_injection": {
        "title": "Se puede insertar contenido falso dentro de páginas legítimas",
        "summary": ("Los datos enviados en un enlace o formulario se muestran en la página sin filtrar. Un atacante "
                    "puede añadir textos, formularios o enlaces falsos en una página real del sitio."),
        "impact": ("Engaños creíbles, como formularios falsos para robar contraseñas, que dañan la confianza en el "
                   "sitio."),
        "action": "Pide al equipo de desarrollo que escape los datos antes de mostrarlos en la página.",
    },
    "crlf_injection": {
        "title": "Se pueden manipular las respuestas que el servidor envía al navegador",
        "summary": ("Un dato del usuario se incluye sin control en la información de control que acompaña a las "
                    "respuestas del servidor. Así se pueden añadir instrucciones no previstas."),
        "impact": ("Podría facilitar el robo de sesiones, la ejecución de código en el navegador o que se sirva "
                   "contenido manipulado a otros usuarios."),
        "action": ("Pide al equipo de desarrollo que rechace los saltos de línea en los datos que usa en esas "
                   "respuestas."),
    },
    "path_traversal": {
        "title": "Se pueden leer archivos internos del servidor",
        "summary": ("Manipulando el nombre de un archivo solicitado, se puede salir de la carpeta prevista y leer "
                    "cualquier archivo del servidor, como configuraciones o claves."),
        "impact": "Exposición de configuraciones, contraseñas y datos almacenados en el servidor.",
        "action": ("Pide al equipo de desarrollo que compruebe que cada archivo solicitado está dentro de la carpeta "
                   "permitida."),
    },
    "open_redirect": {
        "title": "El sitio puede redirigir a los usuarios a páginas fraudulentas",
        "summary": ("Un enlace del propio sitio puede configurarse para enviar al usuario a cualquier web externa. "
                    "Los atacantes lo usan para que sus enlaces fraudulentos parezcan legítimos."),
        "impact": "Engaños más creíbles y, en algunos casos, robo de códigos de acceso.",
        "action": "Pide al equipo de desarrollo que solo permita redirecciones a destinos de una lista autorizada.",
    },
    "ssrf": {
        "title": "El servidor puede ser forzado a conectarse a sistemas internos",
        "summary": ("Un atacante puede indicar a qué dirección se conecta el servidor. Así podría usarlo para llegar "
                    "a sistemas internos o a los datos de configuración de la nube."),
        "impact": "Acceso a sistemas internos y posible robo de credenciales de la infraestructura en la nube.",
        "action": ("Pide al equipo de desarrollo que solo permita conexiones a destinos autorizados y bloquee los "
                   "internos."),
    },
    # -------------------------------------------------------------------------------- API / authentication
    "api_bola": {
        "title": "Un usuario puede ver o modificar datos de otros usuarios",
        "summary": ("Cambiando el identificador de un registro (por ejemplo, un número de pedido), un usuario puede "
                    "acceder a información que pertenece a otras personas."),
        "impact": "Exposición o alteración de datos de otros clientes, con posibles consecuencias legales.",
        "action": ("Pide al equipo de desarrollo que compruebe en cada acceso que el registro pertenece a quien lo "
                   "pide."),
    },
    "api_bfla": {
        "title": "Usuarios sin permisos pueden usar funciones de administración",
        "summary": ("Algunas funciones reservadas a administradores se pueden usar con una cuenta normal, porque el "
                    "servidor no comprueba el rol del usuario."),
        "impact": ("Un usuario cualquiera podría realizar acciones privilegiadas, como cambiar configuraciones o "
                   "datos ajenos."),
        "action": "Pide al equipo de desarrollo que compruebe el rol del usuario en el servidor para cada función.",
    },
    "api_auth_missing": {
        "title": "Funciones o datos sensibles son accesibles sin iniciar sesión",
        "summary": ("Hay funciones o datos que deberían estar protegidos y que cualquiera puede usar o consultar sin "
                    "identificarse."),
        "impact": "Exposición de información o uso indebido de funciones por personas anónimas.",
        "action": ("Pide al equipo de desarrollo que exija inicio de sesión por defecto en todas las funciones del "
                   "servicio."),
    },
    "api_mass_assignment": {
        "title": "Un usuario puede modificar campos protegidos, como su rol o su saldo",
        "summary": ("Al enviar datos, el usuario puede incluir campos adicionales que el sistema acepta sin control, "
                    "como su nivel de permisos, un saldo o el propietario de un registro."),
        "impact": "Un usuario podría darse privilegios o alterar datos sensibles.",
        "action": ("Pide al equipo de desarrollo que acepte solo una lista cerrada de campos modificables en cada "
                   "operación."),
    },
    "api_excessive_data": {
        "title": "El sistema devuelve más datos sensibles de los necesarios",
        "summary": ("Las respuestas del servicio incluyen información sensible que la aplicación no muestra ni "
                    "necesita, pero que se puede ver inspeccionando las comunicaciones."),
        "impact": "Exposición de datos personales o internos a usuarios que no deberían verlos.",
        "action": ("Pide al equipo de desarrollo que defina qué datos devuelve cada respuesta y filtre el resto en "
                   "el servidor."),
    },
    "api_no_rate_limit": {
        "title": "No hay límite de intentos ante peticiones repetidas o automatizadas",
        "summary": ("El servicio no limita cuántas peticiones puede hacer una misma persona o equipo. Eso permite "
                    "probar contraseñas o códigos de forma masiva y abusar de los recursos."),
        "impact": "Acceso a cuentas adivinando contraseñas, recopilación masiva de datos o degradación del servicio.",
        "action": ("Pide al equipo de desarrollo que limite los intentos, sobre todo en el inicio de sesión y las "
                   "contraseñas."),
    },
    "api_jwt_weak": {
        "title": "Las credenciales de sesión podrían falsificarse o reutilizarse",
        "summary": ("Los códigos que identifican a los usuarios conectados están mal protegidos: sin firma válida, "
                    "con una clave débil o sin caducidad. Un atacante podría crear uno falso o reutilizar uno "
                    "antiguo."),
        "impact": "Suplantación de cualquier usuario, incluidos los administradores.",
        "action": "Pide al equipo de desarrollo que firme estos códigos con claves robustas y les ponga caducidad.",
    },
    "api_jwt_sensitive": {
        "title": "Las credenciales de sesión contienen datos sensibles legibles",
        "summary": ("Las credenciales de sesión incluyen información sensible. Su contenido solo está codificado, no "
                    "cifrado, así que cualquiera que tenga una puede leerlo."),
        "impact": "Exposición limitada de datos personales o internos; el riesgo suele ser bajo.",
        "action": "Pide al equipo de desarrollo que no incluya datos sensibles en las credenciales de sesión.",
    },
    "api_inventory": {
        "title": "Siguen activas versiones antiguas o no documentadas del servicio",
        "summary": ("Hay versiones antiguas, funciones de diagnóstico o accesos no documentados que siguen "
                    "respondiendo. Suelen quedar sin las protecciones de la versión actual."),
        "impact": "El riesgo directo es bajo, pero ofrecen vías de entrada menos vigiladas.",
        "action": "Mantén un inventario de los servicios publicados y retira las versiones obsoletas.",
    },
    "graphql_introspection": {
        "title": "El servicio permite descargar la descripción completa de sus funciones",
        "summary": ("El servicio entrega a quien lo pida un mapa completo de sus operaciones y datos, incluidas "
                    "operaciones internas. Facilita a un atacante saber qué probar."),
        "impact": "El riesgo directo es bajo, pero ahorra trabajo a un atacante.",
        "action": "Pide al equipo de desarrollo que desactive esta función de autodescripción en el sitio real.",
    },
    "api_verbose_errors": {
        "title": "Los errores del servicio revelan detalles internos",
        "summary": ("Cuando falla una petición, el servicio devuelve trazas o detalles técnicos internos que ayudan "
                    "a un atacante a entender el sistema."),
        "impact": "Facilita ataques más dirigidos; el impacto directo es limitado.",
        "action": "Pide al equipo de desarrollo que devuelva errores genéricos y guarde el detalle solo internamente.",
    },
    "oauth_misconfig": {
        "title": "El inicio de sesión con cuentas de otros servicios está mal configurado",
        "summary": ("El acceso mediante cuentas de otras plataformas no aplica todas las comprobaciones necesarias, "
                    "por ejemplo sobre a dónde se devuelven los códigos de acceso. Un atacante podría "
                    "interceptarlos."),
        "impact": "Robo de cuentas de usuario a través del proceso de inicio de sesión.",
        "action": ("Pide al equipo de desarrollo que valide las direcciones de retorno y active las protecciones "
                   "recomendadas."),
    },
    "csrf": {
        "title": "Otro sitio podría realizar acciones en nombre del usuario sin su permiso",
        "summary": ("Si un usuario con la sesión iniciada visita una web maliciosa, esta puede hacer que su "
                    "navegador envíe peticiones al sitio y ejecute acciones como si las hubiera pedido él."),
        "impact": "Cambios no deseados en la cuenta del usuario, como modificar datos o confirmar operaciones.",
        "action": ("Pide al equipo de desarrollo que proteja las acciones que modifican datos con códigos de "
                   "verificación."),
    },
    "auth_weakness": {
        "title": "El inicio de sesión tiene debilidades que facilitan entrar sin permiso",
        "summary": ("Se detectaron debilidades en el acceso, como mensajes que revelan qué usuarios existen, falta "
                    "de bloqueo tras intentos repetidos o envío de datos sin cifrar."),
        "impact": "Mayor facilidad para entrar en cuentas de usuarios sin autorización.",
        "action": ("Pide al equipo de desarrollo que use mensajes genéricos, bloquee los intentos repetidos y active "
                   "la verificación en dos pasos."),
    },
    # -------------------------------------------------------------------------------------------- frontend
    "js_secret": {
        "title": "Una contraseña o clave de acceso aparece en el código visible del sitio",
        "summary": ("El código que se descarga en el navegador incluye una credencial. Cualquier visitante puede "
                    "verla y usar el servicio asociado como si fuera la organización."),
        "impact": "Uso indebido del servicio asociado, con posibles costes, fugas de datos o daños a la reputación.",
        "action": ("Pide al equipo de desarrollo que retire la credencial del código, la cambie y la use solo desde "
                   "el servidor."),
    },
    "js_dom_sink": {
        "title": "El código de la página usa funciones peligrosas que podrían aprovecharse",
        "summary": ("El código que se ejecuta en el navegador usa funciones que insertan contenido o ejecutan código "
                    "sin filtrar. Si reciben datos externos, podrían permitir ejecutar código malicioso."),
        "impact": ("El riesgo directo es bajo; se convierte en un fallo real si esas funciones reciben datos de "
                   "terceros."),
        "action": ("Pide al equipo de desarrollo que sustituya esas funciones por alternativas que traten los datos "
                   "como texto."),
    },
    "js_token_storage": {
        "title": "La sesión del usuario se guarda en un lugar del navegador poco protegido",
        "summary": ("El código de acceso de la sesión se guarda en un espacio del navegador que cualquier código de "
                    "la página puede leer. Si se inyecta código malicioso, podría robar la sesión."),
        "impact": "El riesgo directo es bajo, pero agrava las consecuencias de otros fallos.",
        "action": ("Pide al equipo de desarrollo que guarde la sesión en cookies protegidas, inaccesibles desde la "
                   "página."),
    },
    "js_vulnerable_library": {
        "title": "El sitio usa una biblioteca de código con fallos de seguridad conocidos",
        "summary": ("Una biblioteca de código que se descarga en el navegador tiene una versión con fallos "
                    "publicados, que a veces permiten ejecutar código malicioso en las páginas."),
        "impact": ("Según el fallo, podría permitir acciones en nombre de los usuarios o alterar el funcionamiento "
                   "de la página."),
        "action": "Pide al equipo de desarrollo que actualice la biblioteca a una versión corregida.",
    },
    "js_internal_info": {
        "title": "El código visible del sitio revela información interna",
        "summary": ("El código que se descarga en el navegador contiene direcciones internas, rutas de "
                    "administración u otros datos que no deberían ser públicos."),
        "impact": "El riesgo directo es bajo; facilita a un atacante conocer la infraestructura interna.",
        "action": "Pide al equipo de desarrollo que elimine la información interna del código publicado.",
    },
    "js_client_auth": {
        "title": "Algunos controles de acceso se hacen solo en el navegador",
        "summary": ("Las comprobaciones de quién puede hacer qué se realizan en el navegador del usuario, donde se "
                    "pueden manipular o saltar fácilmente."),
        "impact": ("Si el servidor no repite esas comprobaciones, un usuario podría acceder a funciones o datos no "
                   "permitidos."),
        "action": "Pide al equipo de desarrollo que haga todas las comprobaciones de permisos en el servidor.",
    },
    # -------------------------------------------------------------------------------- source code analysis
    "sast_sqli": {
        "title": "El código construye consultas a la base de datos con datos externos",
        "summary": ("El análisis del código encontró consultas a la base de datos construidas con datos que pueden "
                    "venir del usuario. Si es así, permitirían leer o modificar la base de datos."),
        "impact": "Posible lectura o modificación de los datos almacenados si el fallo es alcanzable.",
        "action": ("Pide al equipo de desarrollo que construya las consultas separando siempre los datos de las "
                   "instrucciones."),
    },
    "sast_cmdi": {
        "title": "El código ejecuta órdenes del sistema con datos externos",
        "summary": ("El análisis del código encontró órdenes del sistema operativo construidas con datos que podrían "
                    "venir del exterior. Si un atacante los controla, podría ejecutar sus propias órdenes."),
        "impact": "Posible toma de control del servidor si el fallo es alcanzable.",
        "action": "Pide al equipo de desarrollo que no ejecute órdenes del sistema con datos externos.",
    },
    "sast_code_injection": {
        "title": "El programa podría ejecutar como código un texto llegado del exterior",
        "summary": ("El análisis del código encontró que el programa interpreta y ejecuta como código un texto que "
                    "podría venir de fuera. Un atacante podría ejecutar sus propias instrucciones."),
        "impact": "Posible toma de control de la aplicación y del servidor.",
        "action": "Pide al equipo de desarrollo que elimine la ejecución dinámica de código.",
    },
    "sast_deserialization": {
        "title": "El programa procesa datos externos de una forma que permite ejecutar código",
        "summary": ("El análisis del código encontró que se reconstruyen objetos a partir de datos no confiables con "
                    "métodos inseguros. Un atacante podría enviar datos preparados para ejecutar código."),
        "impact": "Posible toma de control de la aplicación y del servidor.",
        "action": ("Pide al equipo de desarrollo que use formatos de solo datos o limite los tipos de objetos "
                   "aceptados."),
    },
    "sast_xss": {
        "title": "El código muestra contenido en las páginas sin filtrarlo",
        "summary": ("El análisis del código encontró que se desactiva el filtrado automático de las páginas o se "
                    "inserta contenido sin filtrar. Podría permitir ejecutar código no autorizado en el navegador de "
                    "los usuarios."),
        "impact": "Posible robo de sesión y acciones en nombre de los usuarios.",
        "action": ("Pide al equipo de desarrollo que mantenga activo el filtrado automático y no lo desactive con "
                   "datos externos."),
    },
    "sast_path_traversal": {
        "title": "El código abre archivos cuya ubicación podría controlar un atacante",
        "summary": ("El análisis del código encontró accesos a archivos con rutas construidas a partir de datos "
                    "externos. Un atacante podría leer o escribir archivos fuera de la carpeta prevista."),
        "impact": "Posible lectura o modificación de archivos internos del servidor.",
        "action": "Pide al equipo de desarrollo que compruebe que cada ruta queda dentro de la carpeta permitida.",
    },
    "sast_ssrf": {
        "title": "El código hace conexiones a direcciones que podría elegir un atacante",
        "summary": ("El análisis del código encontró conexiones salientes a direcciones construidas con datos "
                    "externos. El servidor podría usarse para llegar a sistemas internos."),
        "impact": "Posible acceso a sistemas internos o a credenciales de la infraestructura en la nube.",
        "action": "Pide al equipo de desarrollo que solo permita destinos autorizados y bloquee las redes internas.",
    },
    "sast_weak_crypto": {
        "title": "El código usa métodos de cifrado anticuados o débiles",
        "summary": ("El análisis del código encontró algoritmos de cifrado obsoletos o claves demasiado cortas, que "
                    "ya no protegen adecuadamente la información."),
        "impact": "Los datos protegidos con estos métodos podrían descifrarse o falsificarse.",
        "action": "Pide al equipo de desarrollo que use algoritmos de cifrado modernos y bibliotecas de confianza.",
    },
    "sast_weak_random": {
        "title": "El código genera códigos de seguridad que se podrían predecir",
        "summary": ("El análisis del código encontró generadores de números aleatorios no aptos para seguridad. Los "
                    "códigos que producen, como los de sesión o recuperación, podrían adivinarse."),
        "impact": "Un atacante podría adivinar códigos de acceso y entrar en cuentas ajenas.",
        "action": "Pide al equipo de desarrollo que use el generador aleatorio seguro de su lenguaje de programación.",
    },
    "sast_password_storage": {
        "title": "Las contraseñas de los usuarios se guardan de forma insegura",
        "summary": ("El análisis del código encontró que las contraseñas se guardan con métodos rápidos o sin "
                    "protección adicional. Si la base de datos se filtra, sería fácil descubrirlas."),
        "impact": ("En caso de filtración se expondrían las contraseñas de los usuarios, que a menudo las reutilizan "
                   "en otros servicios."),
        "action": "Pide al equipo de desarrollo que guarde las contraseñas con un método específico para contraseñas.",
    },
    "sast_hardcoded_secret": {
        "title": "Hay contraseñas o claves escritas directamente en el código",
        "summary": ("El análisis del código encontró credenciales escritas dentro del propio código fuente. "
                    "Cualquiera con acceso al código puede obtenerlas y usarlas."),
        "impact": "Acceso no autorizado a los sistemas o servicios que protegen esas credenciales.",
        "action": "Pide al equipo de desarrollo que cambie esas credenciales y las guarde en un gestor de secretos.",
    },
    "sast_debug": {
        "title": "La aplicación tiene activado el modo de depuración",
        "summary": ("La configuración tiene activado el modo de depuración, pensado solo para desarrollo. En el "
                    "sitio real muestra información interna y a veces ofrece consolas para ejecutar órdenes."),
        "impact": "Exposición de la configuración interna y, en algunos casos, control del servidor.",
        "action": ("Pide al equipo de desarrollo que desactive el modo de depuración en la configuración del sitio "
                   "real."),
    },
    "sast_csrf_disabled": {
        "title": "Está desactivada la protección contra acciones forzadas desde otros sitios",
        "summary": ("La protección que impide que otra web provoque acciones en nombre del usuario está desactivada "
                    "en el código."),
        "impact": "Otro sitio podría hacer que los usuarios conectados realicen acciones sin saberlo.",
        "action": "Pide al equipo de desarrollo que active la protección que incluye su entorno de programación.",
    },
    "sast_tls_verify": {
        "title": "El programa no verifica la identidad de los servidores a los que se conecta",
        "summary": ("El código desactiva la comprobación de certificados en las conexiones salientes. Un atacante en "
                    "la red podría hacerse pasar por el servicio de destino y leer o alterar la información."),
        "impact": "Interceptación o manipulación de los datos intercambiados con otros servicios.",
        "action": "Pide al equipo de desarrollo que mantenga siempre activa la verificación de certificados.",
    },
    "sast_xxe": {
        "title": "El procesamiento de documentos de datos permite leer archivos internos",
        "summary": ("El componente que procesa documentos de intercambio de datos acepta referencias a recursos "
                    "externos. Un documento preparado podría leer archivos del servidor o forzar conexiones "
                    "internas."),
        "impact": "Posible exposición de archivos internos o acceso a otros sistemas desde el servidor.",
        "action": "Pide al equipo de desarrollo que desactive la carga de referencias externas al procesar documentos.",
    },
    "sast_open_redirect": {
        "title": "El código redirige a destinos que podría elegir un atacante",
        "summary": ("El análisis del código encontró redirecciones cuyo destino depende de datos externos. Podrían "
                    "usarse para enviar a los usuarios a webs fraudulentas desde un enlace legítimo."),
        "impact": "Engaños más creíbles usando el nombre del sitio.",
        "action": "Pide al equipo de desarrollo que valide el destino contra una lista de direcciones autorizadas.",
    },
    "sast_template_injection": {
        "title": "El código construye plantillas de páginas con datos externos",
        "summary": ("El análisis del código encontró plantillas generadas a partir de datos que podrían venir del "
                    "usuario. Muchos sistemas de plantillas permiten así ejecutar código en el servidor."),
        "impact": "Posible toma de control del servidor si el fallo es alcanzable.",
        "action": "Pide al equipo de desarrollo que use plantillas fijas y pase los datos solo como variables.",
    },
    "sast_nosql": {
        "title": "El código construye búsquedas en la base de datos con datos sin validar",
        "summary": ("El análisis del código encontró búsquedas en una base de datos construidas con datos externos. "
                    "Un atacante podría alterarlas para saltarse controles o leer otros datos."),
        "impact": "Posible acceso no autorizado o exposición de datos almacenados.",
        "action": "Pide al equipo de desarrollo que valide estrictamente el tipo de los datos antes de usarlos.",
    },
    "sast_ldap": {
        "title": "El código construye búsquedas en el directorio de usuarios con datos externos",
        "summary": ("El análisis del código encontró búsquedas en el directorio de usuarios construidas con datos "
                    "externos sin escapar. Podrían alterarse para saltarse la autenticación o descubrir usuarios."),
        "impact": "Posible acceso no autorizado o exposición de información del directorio.",
        "action": "Pide al equipo de desarrollo que escape los datos antes de usarlos en búsquedas del directorio.",
    },
    "sast_cors_any": {
        "title": "La configuración permite que cualquier web lea las respuestas del servicio",
        "summary": ("La configuración del código autoriza a páginas de cualquier origen a leer las respuestas. Si "
                    "además se permiten sesiones, una web maliciosa podría obtener datos de los usuarios conectados."),
        "impact": "Posible exposición de datos de los usuarios a sitios maliciosos.",
        "action": "Pide al equipo de desarrollo que configure una lista cerrada de sitios autorizados.",
    },
    "sast_missing_auth": {
        "title": "Una función del código no parece exigir inicio de sesión",
        "summary": ("El análisis del código encontró una ruta sin control de acceso visible. Si gestiona datos o "
                    "acciones sensibles, podría ser accesible de forma anónima."),
        "impact": "Si la función es sensible, cualquiera podría usarla sin identificarse; requiere revisión.",
        "action": ("Pide al equipo de desarrollo que confirme si la función necesita protección y, si es así, la "
                   "aplique."),
    },
    "sast_jwt": {
        "title": "El código no verifica correctamente las credenciales de sesión",
        "summary": ("El análisis del código encontró que no se verifica la firma de las credenciales de sesión o que "
                    "se aceptan credenciales sin firmar. Un atacante podría fabricar las suyas."),
        "impact": "Suplantación de cualquier usuario, incluidos los administradores.",
        "action": ("Pide al equipo de desarrollo que verifique siempre la firma con una lista fija de métodos "
                   "permitidos."),
    },
    "sast_logging_sensitive": {
        "title": "Se guardan contraseñas o claves en los registros de actividad",
        "summary": ("El análisis del código encontró que se registran contraseñas o códigos de acceso en los "
                    "archivos de registro. Quien acceda a esos registros podría usarlos."),
        "impact": ("Exposición de credenciales a personas o sistemas que no deberían tenerlas; el riesgo suele ser "
                   "bajo."),
        "action": ("Pide al equipo de desarrollo que no registre secretos y oculte los datos sensibles en los "
                   "registros."),
    },
    "sast_exception_handling": {
        "title": "Algunos errores se gestionan de forma que podrían saltarse controles",
        "summary": ("El análisis del código encontró errores que se ignoran o que, al producirse, dejan pasar la "
                    "operación. Un fallo provocado podría desactivar una comprobación de seguridad."),
        "impact": "El riesgo suele ser bajo, pero en algunos casos permitiría saltarse controles de seguridad.",
        "action": ("Pide al equipo de desarrollo que, ante un error, se deniegue la operación y se registre lo "
                   "ocurrido."),
    },
    "sast_regex_dos": {
        "title": "Un patrón de validación de texto podría bloquear el servicio",
        "summary": ("El código usa un patrón de comprobación de texto que, ante entradas preparadas, tarda muchísimo "
                    "en procesarse. Unas pocas peticiones podrían dejar el servicio sin respuesta."),
        "impact": "Interrupción del servicio para todos los usuarios.",
        "action": "Pide al equipo de desarrollo que simplifique el patrón o limite la longitud del texto que analiza.",
    },
    "sast_insecure_config": {
        "title": "Hay un parámetro de configuración con un valor inseguro",
        "summary": ("El análisis encontró un ajuste de configuración con un valor que reduce la seguridad de la "
                    "aplicación."),
        "impact": "El riesgo suele ser bajo y depende del ajuste concreto.",
        "action": "Pide al equipo de desarrollo que aplique el valor seguro recomendado en el detalle del hallazgo.",
    },
    "sast_generic": {
        "title": "Se encontró un patrón de código potencialmente inseguro",
        "summary": ("El análisis automático del código detectó una forma de programar que suele asociarse a "
                    "problemas de seguridad y conviene revisar."),
        "impact": "El riesgo suele ser bajo y depende del contexto concreto del código.",
        "action": "Pide al equipo de desarrollo que revise el fragmento indicado y aplique la corrección recomendada.",
    },
    # ----------------------------------------------------- secrets / dependencies / infrastructure as code
    "secret_exposed": {
        "title": "Hay contraseñas o claves guardadas en el repositorio de código",
        "summary": ("Se encontraron credenciales en el código o en su historial de cambios. Cualquiera con acceso al "
                    "repositorio puede obtenerlas, aunque se hayan borrado después."),
        "impact": "Acceso no autorizado a los sistemas o servicios que protegen esas credenciales.",
        "action": "Revoca y cambia las credenciales, elimínalas del historial y guárdalas en un gestor de secretos.",
    },
    "vulnerable_dependency": {
        "title": "El proyecto usa componentes de terceros con fallos de seguridad conocidos",
        "summary": ("Una de las bibliotecas o paquetes de los que depende la aplicación tiene un fallo de seguridad "
                    "publicado."),
        "impact": ("Según el fallo y cómo se use el componente, podría exponer datos o permitir ataques contra la "
                   "aplicación."),
        "action": "Pide al equipo de desarrollo que actualice el componente a la versión corregida indicada.",
    },
    "unpinned_dependency": {
        "title": "Los componentes de terceros no tienen una versión fija",
        "summary": ("Algunos componentes se instalan siempre en su versión más reciente. Una versión nueva "
                    "defectuosa o manipulada podría entrar en la aplicación sin que nadie la revise."),
        "impact": "Riesgo bajo pero real de incorporar código malicioso o defectuoso de terceros.",
        "action": "Pide al equipo de desarrollo que fije versiones exactas de todos los componentes.",
    },
    "iac_container_root": {
        "title": "Una aplicación se ejecuta con máximos privilegios dentro de su entorno aislado",
        "summary": ("El entorno aislado donde se ejecuta la aplicación usa el usuario con más privilegios. Si la "
                    "aplicación se ve comprometida, el atacante tendría esos permisos y le sería más fácil llegar al "
                    "servidor."),
        "impact": "Un ataque a la aplicación tendría consecuencias mayores y facilitaría saltar al servidor.",
        "action": "Pide al equipo técnico que ejecute la aplicación con un usuario sin privilegios.",
    },
    "iac_privileged": {
        "title": "Una aplicación tiene permisos que le darían control total del servidor",
        "summary": ("El entorno aislado de la aplicación funciona en modo privilegiado o con acceso directo a "
                    "recursos del servidor. Si la aplicación se ve comprometida, el atacante controlaría todo el "
                    "servidor."),
        "impact": "Toma de control del servidor y de las demás aplicaciones que aloja.",
        "action": "Pide al equipo técnico que elimine el modo privilegiado y los permisos especiales.",
    },
    "iac_secret": {
        "title": "Hay contraseñas o claves escritas en los archivos de infraestructura",
        "summary": ("Se encontraron credenciales dentro de los archivos que describen cómo se despliega la "
                    "infraestructura. Cualquiera con acceso a esos archivos puede usarlas."),
        "impact": "Acceso no autorizado a los sistemas o servicios que protegen esas credenciales.",
        "action": "Pide al equipo técnico que cambie esas credenciales y las cargue desde un gestor de secretos.",
    },
    "iac_insecure_config": {
        "title": "La configuración de la infraestructura no sigue las buenas prácticas",
        "summary": ("Los archivos que definen los servidores o entornos de ejecución contienen ajustes que no siguen "
                    "las recomendaciones de seguridad."),
        "impact": "El riesgo suele ser bajo y depende del ajuste concreto.",
        "action": "Pide al equipo técnico que aplique la recomendación indicada en el detalle del hallazgo.",
    },
    "iac_image_unpinned": {
        "title": "La base de los entornos de ejecución no tiene una versión fija",
        "summary": ("La imagen base de la que parten los entornos de ejecución se indica con una etiqueta que puede "
                    "cambiar en cualquier momento, sin control sobre lo que se despliega."),
        "impact": "Riesgo bajo de desplegar sin querer una versión defectuosa o manipulada.",
        "action": "Pide al equipo técnico que fije la imagen base a una versión exacta e inmutable.",
    },
    # ------------------------------------------------------------------------------ correlation / external
    "route_unprotected": {
        "title": "Una función de la aplicación responde sin pedir credenciales",
        "summary": ("Una ruta que en el código no tiene control de acceso responde en el sistema publicado sin pedir "
                    "credenciales. Se confirmó cruzando el análisis del código con la prueba del sitio."),
        "impact": "Exposición de datos o funciones que deberían estar protegidos.",
        "action": "Pide al equipo de desarrollo que añada control de acceso a esa ruta o que la retire.",
    },
    "route_shadow": {
        "title": "Hay funciones publicadas que no aparecen en el código analizado",
        "summary": ("El sitio publicado responde en direcciones que no constan en el código revisado. Estas "
                    "funciones olvidadas o sin inventariar suelen carecer de controles."),
        "impact": "El riesgo directo es bajo, pero pueden ser una vía de entrada menos vigilada.",
        "action": "Inventaria esas funciones y retira las que no sean necesarias.",
    },
    "external_finding": {
        "title": "Una herramienta externa informó de un posible problema",
        "summary": "Una herramienta de análisis externa detectó un posible problema que todavía debe validarse.",
        "impact": "El impacto depende del problema concreto; consulta el detalle técnico.",
        "action": "Pide al equipo técnico que revise el detalle del hallazgo y confirme si es un problema real.",
    },
}

# Generic texts by category family (prefix), used when a category has no specific entry.
_DEFAULT = "default"
FAMILY_FALLBACK: dict[str, PlainText] = {
    "sast_": {
        "title": "Se encontró un posible fallo de seguridad en el código",
        "summary": "El análisis automático del código fuente detectó una construcción que puede ser insegura.",
        "impact": "El impacto depende de si el fallo es alcanzable desde el exterior; requiere revisión.",
        "action": "Pide al equipo de desarrollo que revise el fragmento indicado y aplique la corrección recomendada.",
    },
    "iac_": {
        "title": "La configuración de la infraestructura podría ser insegura",
        "summary": ("Los archivos que describen cómo se despliegan los servidores contienen un ajuste que conviene "
                    "revisar."),
        "impact": "El impacto depende del ajuste concreto; requiere revisión.",
        "action": "Pide al equipo técnico que revise la configuración indicada y aplique la recomendación.",
    },
    "api_": {
        "title": "Se detectó un posible fallo en los servicios de datos de la aplicación",
        "summary": ("Una de las funciones que la aplicación ofrece a otros programas presenta un posible problema de "
                    "control o de exposición de datos."),
        "impact": "Podría exponer datos o permitir acciones no autorizadas; requiere revisión.",
        "action": "Pide al equipo de desarrollo que revise la función indicada y sus controles de acceso.",
    },
    "js_": {
        "title": "El código que se ejecuta en el navegador tiene un posible problema",
        "summary": ("El código del sitio que se descarga en el navegador presenta una construcción que puede ser "
                    "insegura."),
        "impact": "El impacto depende del caso concreto; requiere revisión.",
        "action": "Pide al equipo de desarrollo que revise el código indicado.",
    },
    "exposed_": {
        "title": "Hay información o servicios internos accesibles públicamente",
        "summary": "Se encontró accesible desde Internet un recurso que normalmente no debería ser público.",
        "impact": "Podría exponer información interna o facilitar otros ataques.",
        "action": "Retira el recurso del acceso público o protégelo con autenticación.",
    },
    "tls_": {
        "title": "La conexión cifrada del sitio tiene una configuración mejorable",
        "summary": ("La forma en que el servidor cifra las comunicaciones no sigue del todo las recomendaciones "
                    "actuales."),
        "impact": "Podría reducir la protección de la información en tránsito; el riesgo suele ser bajo.",
        "action": "Pide al equipo técnico que revise la configuración del cifrado.",
    },
    "cert_": {
        "title": "El certificado de seguridad del sitio presenta un problema",
        "summary": "El certificado que acredita la identidad del sitio no está en un estado correcto.",
        "impact": "Puede provocar avisos en los navegadores y pérdida de confianza de los usuarios.",
        "action": "Revisa el certificado y automatiza su renovación.",
    },
    "dns_": {
        "title": "La configuración del dominio presenta un posible problema",
        "summary": "Los registros públicos del dominio contienen un ajuste que conviene revisar.",
        "impact": "Podría facilitar suplantaciones o revelar información interna; requiere revisión.",
        "action": "Pide al equipo técnico que revise la configuración del dominio.",
    },
    "xss_": {
        "title": "Se podría ejecutar código no autorizado en el navegador de los usuarios",
        "summary": "Se detectó una forma de hacer que el sitio ejecute código ajeno en el navegador de sus visitantes.",
        "impact": "Podría permitir el robo de sesiones y acciones en nombre de los usuarios.",
        "action": "Pide al equipo de desarrollo que valide y escape los datos que se muestran en la página.",
    },
    "missing_": {
        "title": "Falta una medida de protección recomendada en el sitio",
        "summary": "El sitio no tiene activada una protección que los navegadores ofrecen como refuerzo.",
        "impact": "El riesgo directo suele ser bajo; es una medida de refuerzo recomendada.",
        "action": "Pide al equipo técnico que active la protección indicada en el detalle del hallazgo.",
    },
    "default": {
        "title": "Se detectó un posible problema de seguridad",
        "summary": "El análisis encontró un posible problema que conviene revisar.",
        "impact": "El impacto depende del problema concreto; consulta el detalle técnico.",
        "action": "Pide al equipo técnico que revise el detalle del hallazgo y confirme si es un problema real.",
    },
}
_FALLBACK_PREFIXES = sorted((p for p in FAMILY_FALLBACK if p != _DEFAULT), key=len, reverse=True)


def plain_for(category: str) -> PlainText:
    """Plain texts for ``category``; unknown categories get the closest family fallback (always all four keys)."""
    key = (category or "").strip().lower()
    if key in PLAIN:
        return dict(PLAIN[key])
    for prefix in _FALLBACK_PREFIXES:
        if key.startswith(prefix):
            return dict(FAMILY_FALLBACK[prefix])
    return dict(FAMILY_FALLBACK[_DEFAULT])


SEVERITY_PLAIN: dict[str, str] = {
    "critical": "Requiere atención inmediata",
    "high": "Debe corregirse pronto",
    "medium": "Conviene corregirlo en la próxima planificación",
    "low": "Mejora recomendable",
    "info": "Informativo",
}

# severity -> (singular phrase, plural phrase, phrase when there are none)
_COUNT_PHRASES: dict[str, tuple[str, str, str]] = {
    "critical": ("problema crítico requiere atención inmediata", "problemas críticos requieren atención inmediata",
                 "Sin problemas críticos"),
    "high": ("problema grave debe corregirse pronto", "problemas graves deben corregirse pronto",
             "Sin problemas graves"),
    "medium": ("problema de gravedad media debería corregirse en la próxima planificación",
               "problemas de gravedad media deberían corregirse en la próxima planificación",
               "Sin problemas de gravedad media"),
    "low": ("problema leve puede corregirse cuando sea posible", "problemas leves pueden corregirse cuando sea posible",
            "Sin problemas leves"),
    "info": ("observación informativa, sin riesgo directo", "observaciones informativas, sin riesgo directo",
             "Sin observaciones informativas"),
}
_COUNT_DEFAULT = ("problema detectado", "problemas detectados", "Sin problemas detectados")


def plain_count(severity: str, n: int) -> str:
    """Natural Spanish sentence for ``n`` findings of a severity, e.g. "1 problema grave debe corregirse pronto"."""
    singular, plural, none = _COUNT_PHRASES.get((severity or "").strip().lower(), _COUNT_DEFAULT)
    n = max(int(n), 0)
    if n == 0:
        return none
    return f"{n} {singular if n == 1 else plural}"
