# vigia:ignore-file — catálogo de patrones de detección (las expresiones regulares se detectarían a sí mismas)
"""M08 / M05 — Static analysis (SAST) with Vigía's own rule engine.

* Lexical rules for Python, JavaScript, TypeScript, PHP, Java, C#, Go, Ruby, HTML/templates, CSS and SQL.
  A rule whose sink line (or the enclosing lines) also contains a user-input source is ``likely``;
  otherwise ``suspected``. Static findings are never ``confirmed`` on their own.
* Python AST analysis with intra-procedural taint tracking (request/argv → sink).
* Framework configuration checks (Django, Flask, Express, Spring, ASP.NET, Laravel, Rails, PHP).
* Route extraction with authentication detection for code ↔ deployment correlation.
Interprocedural data-flow is delegated to Opengrep/Semgrep when installed.
"""
from __future__ import annotations

import ast
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from vigia.core.context import ScanContext
from vigia.core.findings import FindingDraft
from vigia.core.module import Module
from vigia.modules.source import is_test_path, iter_files, language, read_text

TAINT = {
    "python": re.compile(r"request\.(args|form|values|json|data|files|GET|POST|body|query_params|cookies|headers|"
                         r"get_json|path_params)|\binput\(|sys\.argv|\bkwargs\[|self\.request\."),
    "javascript": re.compile(r"\breq\.(query|body|params|headers|cookies)|request\.(query|body|params)|ctx\.(query|params|"
                             r"request\.body)|location\.(hash|search|href)|document\.URL|process\.argv|event\.body"),
    "php": re.compile(r"\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)|\$request->(input|get|query|post|all)\(|Input::get|"
                      r"request\(\)->"),
    "java": re.compile(r"getParameter\(|getHeader\(|@RequestParam|@PathVariable|@RequestBody|getQueryString\(|"
                       r"getInputStream\(|getCookies\("),
    "csharp": re.compile(r"Request\.(Query|Form|Params|QueryString|Cookies|Headers|Body)|\[From(Query|Body|Route|Form)\]"),
    "go": re.compile(r"r\.URL\.Query\(\)|r\.FormValue\(|r\.PostFormValue\(|c\.Query\(|c\.Param\(|c\.PostForm\(|"
                     r"mux\.Vars\(|r\.Body"),
    "ruby": re.compile(r"\bparams\[|params\.|request\.(params|body|query_string)|cookies\["),
}
TAINT["typescript"] = TAINT["javascript"]


@dataclass(frozen=True)
class Rule:
    id: str
    langs: tuple[str, ...]
    category: str
    pattern: re.Pattern[str]
    title: str
    taint: bool = True  # require/consider user input near the sink for 'likely'
    always: str | None = None  # fixed confidence regardless of taint
    exclude: re.Pattern[str] | None = None
    require_taint: bool = False  # report only when user input is visible near the sink


def R(id_: str, langs: str, cat: str, pat: str, title: str, taint: bool = True, always: str | None = None,
      exclude: str | None = None, flags: int = 0, require_taint: bool = False) -> Rule:
    return Rule(id_, tuple(langs.split(",")), cat, re.compile(pat, flags), title, taint, always,
                re.compile(exclude) if exclude else None, require_taint)


JS = "javascript,typescript"
RULES: list[Rule] = [
    # ---------------------------------------------------------------- Python
    R("py-sqli-format", "python", "sast_sqli", r"\.(execute|executemany|raw|extra)\(\s*(f[\"']|[\"'][^\"']*[\"']\s*(%|\+|\.format))",
      "SQL construida con formato de cadenas"),
    R("py-subprocess-shell", "python", "sast_cmdi", r"subprocess\.\w+\([^)]*shell\s*=\s*True", "subprocess con shell=True"),
    R("py-os-system", "python", "sast_cmdi", r"\bos\.(system|popen|spawn\w*)\(", "os.system/os.popen"),
    R("py-eval", "python", "sast_code_injection", r"(?<![\w.])(eval|exec)\(\s*(?![\"'])", "eval/exec con expresión no literal"),
    R("py-pickle", "python", "sast_deserialization", r"\b(pickle|cPickle|dill|shelve|jsonpickle)\.(loads?|open|decode)\(",
      "Deserialización con pickle/jsonpickle", taint=False, always="likely"),
    R("py-yaml-load", "python", "sast_deserialization", r"\byaml\.(load|load_all)\((?![^)]*(Safe|Base)Loader)",
      "yaml.load sin SafeLoader", taint=False, always="likely"),
    R("py-tls-verify", "python", "sast_tls_verify", r"verify\s*=\s*False|_create_unverified_context|CERT_NONE",
      "Verificación TLS desactivada", taint=False, always="likely"),
    R("py-weak-hash", "python", "sast_weak_crypto", r"hashlib\.(md5|sha1)\((?![^)]*usedforsecurity\s*=\s*False)",
      "Hash débil (MD5/SHA1)", taint=False, always="suspected"),
    R("py-weak-cipher", "python", "sast_weak_crypto", r"\b(DES|DES3|ARC4|Blowfish)\.new\(|MODE_ECB", "Cifrado débil o modo ECB",
      taint=False, always="likely"),
    R("py-weak-random", "python", "sast_weak_random",
      r"(token|secret|password|passwd|otp|nonce|salt|key|code)\w*\s*=.*\brandom\.(random|randint|choice|choices|getrandbits)\(",
      "random usado para valores de seguridad", taint=False, always="likely", flags=re.I),
    R("py-flask-debug", "python", "sast_debug", r"\.run\([^)]*debug\s*=\s*True", "Flask/Werkzeug con debug=True", taint=False,
      always="likely"),
    R("py-django-debug", "python", "sast_debug", r"^\s*DEBUG\s*=\s*True\b", "Django DEBUG=True", taint=False, always="likely",
      flags=re.M),
    R("py-ssti", "python", "sast_template_injection", r"render_template_string\(\s*(?![\"'])|jinja2\.Template\(\s*(?![\"'])|"
      r"Environment\([^)]*\)\.from_string\(\s*(?![\"'])", "Plantilla construida dinámicamente"),
    R("py-mark-safe", "python", "sast_xss", r"\b(mark_safe|Markup|SafeString)\(\s*(?![\"'])", "Contenido marcado como seguro"),
    R("py-autoescape-off", "python", "sast_xss", r"autoescape\s*=\s*False", "Autoescape desactivado", taint=False,
      always="likely"),
    R("py-xxe", "python", "sast_xxe", r"lxml\.etree\.(parse|fromstring|XMLParser)\(|XMLParser\([^)]*resolve_entities\s*=\s*True|"
      r"xml\.dom\.(minidom|pulldom)\.parse|xml\.sax\.make_parser", "Parser XML sin protección contra XXE", taint=False,
      always="suspected"),
    R("py-ssrf", "python", "sast_ssrf", r"(requests|httpx|urllib\.request|aiohttp\.ClientSession\(\)|session)\.(get|post|put|"
      r"request|urlopen)\(\s*[a-z_]*(url|uri|link|target|endpoint)", "Petición saliente con URL variable",
      require_taint=True),
    R("py-path", "python", "sast_path_traversal", r"(open|send_file|send_from_directory|FileResponse)\(\s*(?![\"'])[^)]*"
      r"(request|filename|path|name)", "Acceso a fichero con ruta variable", require_taint=True),
    R("py-redirect", "python", "sast_open_redirect", r"redirect\(\s*request\.(args|GET|POST|form|values)",
      "Redirección con destino de la petición", taint=False, always="likely"),
    R("py-jwt-noverify", "python", "sast_jwt", r"jwt\.decode\([^)]*(verify\s*=\s*False|verify_signature[\"']?\s*:\s*False|"
      r"algorithms\s*=\s*\[?[\"']none)", "jwt.decode sin verificar la firma", taint=False, always="likely"),
    R("py-password-hash", "python", "sast_password_storage", r"hashlib\.(md5|sha1|sha256|sha512)\([^)]*(password|passwd|pwd)",
      "Contraseña con hash rápido sin sal", taint=False, always="likely", flags=re.I),
    R("py-csrf-exempt", "python", "sast_csrf_disabled", r"@csrf_exempt|WTF_CSRF_ENABLED\s*=\s*False|csrf\.exempt",
      "Protección CSRF desactivada", taint=False, always="likely"),
    R("py-cors-any", "python", "sast_cors_any", r"CORS_ORIGIN_ALLOW_ALL\s*=\s*True|CORS_ALLOW_ALL_ORIGINS\s*=\s*True|"
      r"allow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\][^)]*allow_credentials\s*=\s*True|CORS\([^)]*origins\s*=\s*[\"']\*",
      "CORS abierto", taint=False, always="likely"),
    R("py-log-secret", "python", "sast_logging_sensitive", r"(log|logger|logging)\.(debug|info|warning|error|critical)\([^)]*"
      r"(password|passwd|secret|token)", "Posible registro de secretos", taint=False, always="suspected", flags=re.I),
    R("py-except-pass", "python", "sast_exception_handling", r"except(\s+(Exception|BaseException))?\s*:\s*\n\s*pass\b",
      "Excepción silenciada", taint=False, always="suspected"),
    R("py-allowed-hosts", "python", "sast_insecure_config", r"ALLOWED_HOSTS\s*=\s*\[\s*[\"']\*[\"']", "ALLOWED_HOSTS='*'",
      taint=False, always="likely"),
    R("py-cookie-insecure", "python", "sast_insecure_config", r"(SESSION|CSRF)_COOKIE_(SECURE|HTTPONLY)\s*=\s*False",
      "Cookie de sesión sin Secure/HttpOnly", taint=False, always="likely"),
    R("py-mktemp", "python", "sast_insecure_config", r"tempfile\.mktemp\(", "tempfile.mktemp (condición de carrera)",
      taint=False, always="likely"),
    R("py-chmod-777", "python", "sast_insecure_config", r"chmod\([^)]*0o?777", "Permisos 777", taint=False, always="likely"),
    R("py-assert-auth", "python", "sast_exception_handling", r"^\s*assert\s+.*(is_authenticated|is_admin|has_perm|user)",
      "assert usado para control de acceso (se elimina con -O)", taint=False, always="likely", flags=re.M),
    # ---------------------------------------------------------------- JavaScript / TypeScript
    R("js-eval", JS, "sast_code_injection", r"(?<![\w.])eval\(\s*(?![\"'`])|new Function\(|vm\.(runInNewContext|runInThisContext|"
      r"runInContext)\(|setTimeout\(\s*[\"'`]", "Evaluación dinámica de código"),
    R("js-exec", JS, "sast_cmdi", r"(child_process\.)?\b(exec|execSync)\(\s*(`[^`]*\$\{|[^\"'`)]|[\"'][^\"']*[\"']\s*\+)|"
      r"spawn\([^)]*shell\s*:\s*true", "Ejecución de comandos con datos variables"),
    R("js-sqli", JS, "sast_sqli", r"\.(query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe)\(\s*(`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+)",
      "SQL construida con interpolación"),
    R("js-nosql-where", JS, "sast_nosql", r"\$where|\.(find|findOne|updateOne|deleteOne|aggregate)\(\s*req\.(body|query)",
      "Consulta NoSQL con objeto de la petición"),
    R("js-innerhtml", JS, "sast_xss", r"\.innerHTML\s*[+]?=\s*(?![\"'`]\s*;)|\.outerHTML\s*=|document\.write\(|"
      r"insertAdjacentHTML\(|dangerouslySetInnerHTML|bypassSecurityTrust\w+\(", "Inserción de HTML sin codificar"),
    R("js-res-send", JS, "sast_xss", r"res\.(send|write|end)\(\s*[^)]*req\.(query|body|params)", "Respuesta con datos de la petición",
      taint=False, always="likely"),
    R("js-path", JS, "sast_path_traversal", r"(readFile|readFileSync|createReadStream|sendFile|download|unlink|writeFile)\(\s*"
      r"[^)]*req\.(query|body|params)", "Acceso a fichero con ruta de la petición", taint=False, always="likely"),
    R("js-ssrf", JS, "sast_ssrf", r"\b(axios(\.\w+)?|fetch|got|request|needle|superagent\.\w+|http\.get|https\.get)\(\s*"
      r"[^)]*req\.(query|body|params)", "Petición saliente con URL de la petición", taint=False, always="likely"),
    R("js-redirect", JS, "sast_open_redirect", r"res\.redirect\(\s*[^)]*req\.(query|body|params)",
      "Redirección con destino de la petición", taint=False, always="likely"),
    R("js-weak-random", JS, "sast_weak_random", r"(token|secret|password|otp|nonce|salt|key|session|code)\w*\s*[:=][^;\n]*"
      r"Math\.random\(\)", "Math.random para valores de seguridad", taint=False, always="likely", flags=re.I),
    R("js-weak-hash", JS, "sast_weak_crypto", r"createHash\(\s*[\"'](md5|sha1)[\"']|createCipher\(|[\"'](des|des-ede3?(-cbc)?|"
      r"des-cbc|rc4|aes-\d+-ecb)[\"']", "Criptografía débil", taint=False, always="suspected", flags=re.I),
    R("js-tls", JS, "sast_tls_verify", r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0",
      "Verificación TLS desactivada", taint=False, always="likely"),
    R("js-jwt", JS, "sast_jwt", r"algorithms\s*:\s*\[[^\]]*[\"']none[\"']|ignoreExpiration\s*:\s*true|jwt\.decode\([^)]*\)\s*;?"
      r"\s*(if|return|const|let)", "Uso inseguro de JWT", taint=False, always="suspected"),
    R("js-cors", JS, "sast_cors_any", r"origin\s*:\s*(true|[\"']\*[\"'])[^}]*credentials\s*:\s*true|"
      r"Access-Control-Allow-Origin[\"']\s*,\s*req\.headers\.origin", "CORS abierto con credenciales", taint=False,
      always="likely"),
    R("js-deser", JS, "sast_deserialization", r"node-serialize|\.unserialize\(|serialize\.unserialize|"
      r"yaml\.load\((?![^)]*(JSON_SCHEMA|FAILSAFE))", "Deserialización insegura", taint=False, always="suspected"),
    R("js-ssti", JS, "sast_template_injection", r"(ejs|pug|jade|handlebars|nunjucks|_)\.(render|compile|template)\(\s*"
      r"[^)]*req\.(query|body|params)", "Plantilla con datos de la petición", taint=False, always="likely"),
    R("js-regex-input", JS, "sast_regex_dos", r"new RegExp\(\s*[^)]*req\.(query|body|params)",
      "Expresión regular construida con la petición", taint=False, always="likely"),
    R("js-session-insecure", JS, "sast_insecure_config", r"(secure|httpOnly)\s*:\s*false", "Cookie sin Secure/HttpOnly",
      taint=False, always="suspected"),
    R("js-static-root", JS, "sast_insecure_config", r"express\.static\(\s*[\"']\.?/?[\"']\s*\)|express\.static\(\s*__dirname\s*\)",
      "Directorio raíz servido como estático", taint=False, always="likely"),
    # ---------------------------------------------------------------- PHP
    R("php-sqli", "php", "sast_sqli", r"(mysql_query|mysqli_query|pg_query|->query|->exec|->prepare)\(\s*[^)]*(\"[^\"]*\$\w|"
      r"\.\s*\$)", "SQL construida con variables"),
    R("php-cmdi", "php", "sast_cmdi", r"\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\(|`[^`]*\$", "Ejecución "
      "de comandos"),
    R("php-eval", "php", "sast_code_injection", r"\b(eval|assert|create_function)\(\s*\$|preg_replace\(\s*[\"'][^\"']*/[a-z]*e[a-z]*"
      r"[\"']", "Evaluación de código"),
    R("php-include", "php", "sast_path_traversal", r"\b(include|require)(_once)?\s*\(?\s*[^;]*\$_(GET|POST|REQUEST|COOKIE)",
      "include/require con datos de la petición", taint=False, always="likely"),
    R("php-file", "php", "sast_path_traversal", r"(file_get_contents|fopen|readfile|file|unlink|copy)\(\s*[^)]*\$_(GET|POST|REQUEST)",
      "Acceso a fichero con datos de la petición", taint=False, always="likely"),
    R("php-unserialize", "php", "sast_deserialization", r"\bunserialize\(", "unserialize()"),
    R("php-echo", "php", "sast_xss", r"(echo|print)\s*\(?\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)", "Salida directa de la petición",
      taint=False, always="likely"),
    R("php-ssrf", "php", "sast_ssrf", r"(file_get_contents|curl_init|fsockopen)\(\s*\$_(GET|POST|REQUEST)|CURLOPT_URL\s*,\s*\$_",
      "Petición saliente con URL de la petición", taint=False, always="likely"),
    R("php-weak-hash", "php", "sast_password_storage", r"\b(md5|sha1)\(\s*\$\w*pass", "Contraseña con MD5/SHA1", taint=False,
      always="likely", flags=re.I),
    R("php-redirect", "php", "sast_open_redirect", r"header\(\s*[\"']Location:\s*[\"']?\s*\.\s*\$_(GET|POST|REQUEST)",
      "Redirección con destino de la petición", taint=False, always="likely"),
    R("php-display-errors", "php", "sast_debug", r"display_errors[\"']?\s*,\s*[\"']?(1|On|true)", "display_errors activado",
      taint=False, always="likely", flags=re.I),
    R("php-ldap", "php", "sast_ldap", r"ldap_search\([^)]*\$_(GET|POST|REQUEST)", "Filtro LDAP con datos de la petición",
      taint=False, always="likely"),
    R("php-xxe", "php", "sast_xxe", r"libxml_disable_entity_loader\(\s*false|LIBXML_NOENT", "Entidades XML externas habilitadas",
      taint=False, always="likely"),
    R("php-blade-raw", "php", "sast_xss", r"\{!!\s*\$", "Salida Blade sin escapar", taint=False, always="suspected"),
    # ---------------------------------------------------------------- Java / Kotlin
    R("java-sqli", "java", "sast_sqli", r"(executeQuery|executeUpdate|execute|prepareStatement|createQuery|createNativeQuery|"
      r"queryForObject|queryForList)\(\s*\"[^\"]*\"\s*\+", "SQL concatenada"),
    R("java-cmdi", "java", "sast_cmdi", r"Runtime\.getRuntime\(\)\.exec\(|new ProcessBuilder\(", "Ejecución de comandos"),
    R("java-deser", "java", "sast_deserialization", r"new ObjectInputStream\(|\.readObject\(\)|XMLDecoder|enableDefaultTyping|"
      r"JsonTypeInfo\.Id\.CLASS|activateDefaultTyping", "Deserialización insegura", taint=False, always="likely"),
    R("java-xxe", "java", "sast_xxe", r"(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory)\."
      r"newInstance\(\)", "Parser XML (verifica FEATURE_SECURE_PROCESSING)", taint=False, always="suspected"),
    R("java-weak-crypto", "java", "sast_weak_crypto", r"MessageDigest\.getInstance\(\s*\"(MD5|SHA-?1)\"|Cipher\.getInstance\("
      r"\s*\"(DES|DESede|RC4|AES/ECB|AES\")", "Criptografía débil", taint=False, always="likely"),
    R("java-random", "java", "sast_weak_random", r"new Random\(\)", "java.util.Random (no criptográfico)", taint=False,
      always="suspected"),
    R("java-trustall", "java", "sast_tls_verify", r"checkServerTrusted\([^)]*\)\s*(throws [\w.]+\s*)?\{\s*\}|"
      r"ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|setHostnameVerifier\(\s*\([^)]*\)\s*->\s*true",
      "Validación TLS desactivada", taint=False, always="likely"),
    R("java-csrf", "java", "sast_csrf_disabled", r"csrf\(\)\.disable\(\)|csrf\(\s*\w+\s*->\s*\w+\.disable\(\)\)|"
      r"csrf\(AbstractHttpConfigurer::disable\)", "CSRF desactivado en Spring Security", taint=False, always="likely"),
    R("java-path", "java", "sast_path_traversal", r"new (File|FileInputStream|FileReader)\(\s*[^)]*getParameter",
      "Fichero con ruta de la petición", taint=False, always="likely"),
    R("java-xss", "java", "sast_xss", r"getWriter\(\)\.(print|println|write)\(\s*[^)]*getParameter", "Salida con datos de la "
      "petición", taint=False, always="likely"),
    R("java-redirect", "java", "sast_open_redirect", r"sendRedirect\(\s*[^)]*getParameter", "Redirección con destino de la "
      "petición", taint=False, always="likely"),
    R("java-cors", "java", "sast_cors_any", r"@CrossOrigin\(\s*(origins\s*=\s*\"\*\"\s*)?\)|allowedOrigins\(\s*\"\*\"\s*\)",
      "CORS abierto", taint=False, always="suspected"),
    R("java-spel", "java", "sast_template_injection", r"parseExpression\(\s*(?!\")", "Expresión SpEL dinámica"),
    # ---------------------------------------------------------------- C#
    R("cs-sqli", "csharp", "sast_sqli", r"(SqlCommand|ExecuteSqlRaw|FromSqlRaw|ExecuteQuery|SqlDataAdapter)\(\s*(\$\"|\"[^\"]*\""
      r"\s*\+)", "SQL concatenada o interpolada"),
    R("cs-process", "csharp", "sast_cmdi", r"Process\.Start\(", "Process.Start"),
    R("cs-deser", "csharp", "sast_deserialization", r"BinaryFormatter|NetDataContractSerializer|LosFormatter|SoapFormatter|"
      r"ObjectStateFormatter|TypeNameHandling\.(All|Auto|Objects)|SimpleTypeResolver", "Deserialización insegura",
      taint=False, always="likely"),
    R("cs-weak-crypto", "csharp", "sast_weak_crypto", r"\b(MD5|SHA1)\.Create\(|DESCryptoServiceProvider|RC2|TripleDES|"
      r"CipherMode\.ECB", "Criptografía débil", taint=False, always="likely"),
    R("cs-tls", "csharp", "sast_tls_verify", r"(ServerCertificateValidationCallback|ServerCertificateCustomValidationCallback)"
      r"\s*\+?=\s*[^;]*=>\s*true", "Validación TLS desactivada", taint=False, always="likely"),
    R("cs-raw", "csharp", "sast_xss", r"Html\.Raw\(", "Html.Raw", taint=False, always="suspected"),
    R("cs-devpage", "csharp", "sast_debug", r"UseDeveloperExceptionPage\(\)", "Página de excepción de desarrollo",
      taint=False, always="suspected"),
    R("cs-cors", "csharp", "sast_cors_any", r"AllowAnyOrigin\(\)[\s\S]{0,80}AllowCredentials\(\)", "CORS abierto con credenciales",
      taint=False, always="likely"),
    R("cs-xxe", "csharp", "sast_xxe", r"DtdProcessing\s*=\s*DtdProcessing\.Parse|XmlResolver\s*=\s*new XmlUrlResolver",
      "Procesamiento DTD habilitado", taint=False, always="likely"),
    R("cs-redirect", "csharp", "sast_open_redirect", r"Redirect\(\s*Request\.(Query|Form)", "Redirección con destino de la "
      "petición", taint=False, always="likely"),
    R("cs-path", "csharp", "sast_path_traversal", r"File\.(ReadAllText|ReadAllBytes|OpenRead|Delete)\(\s*[^)]*Request\.",
      "Fichero con ruta de la petición", taint=False, always="likely"),
    # ---------------------------------------------------------------- Go
    R("go-sqli", "go", "sast_sqli", r"\.(Query|Exec|QueryRow|QueryContext|ExecContext)\(\s*(fmt\.Sprintf\(|\"[^\"]*\"\s*\+)",
      "SQL construida con Sprintf/concatenación"),
    R("go-cmd", "go", "sast_cmdi", r"exec\.Command(Context)?\(\s*(\"(sh|bash|cmd|powershell)\"|[^\"])", "exec.Command con shell "
      "o binario variable"),
    R("go-tls", "go", "sast_tls_verify", r"InsecureSkipVerify\s*:\s*true", "InsecureSkipVerify", taint=False, always="likely"),
    R("go-weak-crypto", "go", "sast_weak_crypto", r"\"crypto/(md5|sha1|des|rc4)\"", "Criptografía débil", taint=False,
      always="suspected"),
    R("go-path", "go", "sast_path_traversal", r"(os\.Open|os\.ReadFile|ioutil\.ReadFile|http\.ServeFile)\([^)]*(r\.URL|"
      r"r\.FormValue|c\.Query|c\.Param)", "Fichero con ruta de la petición", taint=False, always="likely"),
    R("go-ssrf", "go", "sast_ssrf", r"http\.(Get|Post|NewRequest)\([^)]*(r\.URL|r\.FormValue|c\.Query)", "Petición saliente con "
      "URL de la petición", taint=False, always="likely"),
    R("go-xss", "go", "sast_xss", r"template\.HTML\(|fmt\.Fprintf?\(\s*w\s*,[^)]*(r\.URL|r\.FormValue)", "HTML sin escapar"),
    R("go-pprof", "go", "sast_debug", r"_\s+\"net/http/pprof\"", "pprof importado (endpoints de depuración)", taint=False,
      always="likely"),
    # ---------------------------------------------------------------- Ruby
    R("rb-sqli", "ruby", "sast_sqli", r"\.(where|find_by_sql|execute|order|group|having|joins|pluck)\(\s*\"[^\"]*#\{", "SQL "
      "interpolada"),
    R("rb-cmd", "ruby", "sast_cmdi", r"\b(system|exec|spawn|IO\.popen|Open3\.\w+)\(|%x\(|`[^`]*#\{", "Ejecución de comandos"),
    R("rb-eval", "ruby", "sast_code_injection", r"\b(eval|instance_eval|class_eval|module_eval)\(|\.send\(\s*params",
      "Evaluación dinámica"),
    R("rb-deser", "ruby", "sast_deserialization", r"Marshal\.load|YAML\.load\((?![^)]*safe)|Oj\.load\(", "Deserialización "
      "insegura", taint=False, always="likely"),
    R("rb-html-safe", "ruby", "sast_xss", r"\.html_safe\b|\braw\(", "Contenido marcado como seguro"),
    R("rb-redirect", "ruby", "sast_open_redirect", r"redirect_to\s+params\[", "Redirección con destino de la petición",
      taint=False, always="likely"),
    R("rb-csrf", "ruby", "sast_csrf_disabled", r"skip_before_action\s+:verify_authenticity_token|protect_from_forgery\s+with:\s*"
      r":null_session", "CSRF desactivado", taint=False, always="likely"),
    R("rb-permit-all", "ruby", "sast_insecure_config", r"params\.permit!", "params.permit! (mass assignment)", taint=False,
      always="likely"),
    R("rb-tls", "ruby", "sast_tls_verify", r"VERIFY_NONE", "Verificación TLS desactivada", taint=False, always="likely"),
    # ---------------------------------------------------------------- HTML / templates / CSS / SQL / config
    R("html-blank", "html", "sast_insecure_config", r"target=[\"']_blank[\"'](?![^>]*rel=[\"'][^\"']*noopener)",
      "target=_blank sin rel=noopener", taint=False, always="suspected"),
    R("html-form-http", "html", "sast_insecure_config", r"<form[^>]+action=[\"']http://", "Formulario enviado por HTTP",
      taint=False, always="likely"),
    R("html-script-http", "html,css", "sast_insecure_config", r"<script[^>]+src=[\"']http://|@import\s+url\(\s*[\"']?http://",
      "Recurso cargado por HTTP", taint=False, always="likely"),
    R("tpl-unescaped", "html", "sast_xss", r"\{\{\s*[\w.\[\]]+\s*\|\s*safe\s*\}\}|\{\{\{\s*[\w.]+\s*\}\}\}|<%-\s*[\w.]+|"
      r"\{%\s*autoescape\s+(false|off)", "Variable de plantilla sin escapar", taint=False, always="suspected"),
    R("css-expression", "css", "sast_insecure_config", r"expression\s*\(", "CSS expression()", taint=False, always="suspected"),
    R("sql-grant-all", "sql", "sast_insecure_config", r"GRANT\s+ALL\s+PRIVILEGES\s+ON\s+\*\.\*|GRANT\s+ALL\s+ON\s+\*", "Privilegios "
      "globales en la base de datos", taint=False, always="likely", flags=re.I),
    R("sql-password", "sql", "sast_hardcoded_secret", r"IDENTIFIED\s+BY\s+['\"][^'\"]{3,}['\"]|PASSWORD\s+['\"][^'\"]{3,}['\"]",
      "Contraseña en script SQL", taint=False, always="likely", flags=re.I),
    R("cfg-customerrors", "config", "sast_debug", r"<customErrors\s+mode=\"Off\"|<compilation[^>]+debug=\"true\"",
      "Errores detallados o depuración en web.config", taint=False, always="likely"),
    R("cfg-php-ini", "config", "sast_debug", r"^\s*display_errors\s*=\s*(On|1)", "display_errors en php.ini", taint=False,
      always="likely", flags=re.M | re.I),
]

AUTH_HINT = re.compile(r"login_required|jwt_required|auth_required|permission_required|requires_auth|Depends\(\s*(get_current_\w+|"
                       r"\w*auth\w*|\w*user\w*|oauth2_scheme)|@PreAuthorize|@Secured|@RolesAllowed|\[Authorize|"
                       r"authenticate|isAuthenticated|ensureLoggedIn|requireAuth|verifyToken|passport\.authenticate|protect\b|"
                       r"middleware\(\s*\[?['\"]auth|before_action\s+:authenticate|authorize|IsAuthenticated|"
                       r"permission_classes|LoginRequiredMixin|auth\.\w+\(|checkAuth|withAuth|guard", re.I)
ROUTE_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("python", "flask/fastapi", re.compile(r"@\w+\.(route|get|post|put|patch|delete|api_route)\(\s*[\"']([^\"']+)[\"']"
                                           r"(?:[^)]*methods\s*=\s*\[([^\]]*)\])?")),
    ("python", "django", re.compile(r"\b(re_)?path\(\s*r?[\"']([^\"']*)[\"']\s*,\s*([\w.]+)")),
    ("javascript", "express", re.compile(r"\b(?:app|router|server|api)\.(get|post|put|patch|delete|all|use)\(\s*[\"'`](/[^\"'`]*)"
                                         r"[\"'`]")),
    ("typescript", "express/nest", re.compile(r"(?:\b(?:app|router|server)\.(get|post|put|patch|delete|all)\(\s*[\"'`](/[^\"'`]*)"
                                              r"[\"'`])|@(Get|Post|Put|Patch|Delete)\(\s*[\"'`]?([^\"'`)]*)")),
    ("java", "spring", re.compile(r"@(Get|Post|Put|Patch|Delete|Request)Mapping\(\s*(?:value\s*=\s*|path\s*=\s*)?\{?\s*\"([^\"]*)\"")),
    ("php", "laravel", re.compile(r"Route::(get|post|put|patch|delete|any|match)\(\s*['\"]([^'\"]*)['\"]")),
    ("ruby", "rails", re.compile(r"^\s*(get|post|put|patch|delete|match)\s+['\"]([^'\"]+)['\"]", re.M)),
    ("csharp", "aspnet", re.compile(r"\[(?:Http(Get|Post|Put|Patch|Delete)|Route)\(\s*\"([^\"]*)\"")),
    ("go", "net/http/gin/echo", re.compile(r"\.(GET|POST|PUT|PATCH|DELETE|HandleFunc|Handle|Any)\(\s*\"(/[^\"]*)\"")),
]


class SastModule(Module):
    name = "sast"
    title = "Análisis estático de código (SAST)"
    phase = "recon"  # runs alongside reconnaissance: routes feed the correlation phase
    needs_source = True

    async def run(self, ctx: ScanContext) -> None:
        import asyncio
        ignored: list[str] = []
        drafts, routes, langs = await asyncio.to_thread(analyse_tree, ctx.source_dir, ignored)
        if ignored:
            ctx.emit("info", self.name, f"{len(ignored)} ficheros excluidos del SAST por el pragma vigia:ignore-file",
                     {"ficheros": ignored[:50]})
        ctx.kb.languages = dict(langs)
        ctx.kb.code_routes = routes
        ctx.emit("info", self.name, f"Lenguajes: {dict(langs.most_common(8))}; {len(routes)} rutas extraídas; "
                 f"{len(drafts)} hallazgos estáticos")
        for d in drafts:
            ctx.add(d)


def analyse_tree(root: Path, ignored_files: list[str] | None = None) -> tuple[list[FindingDraft], list[dict], Counter]:
    ignored_files = ignored_files if ignored_files is not None else []
    drafts: list[FindingDraft] = []
    routes: list[dict] = []
    langs: Counter = Counter()
    per_rule: Counter = Counter()
    for path, rel in iter_files(root):
        lang = language(path)
        if not lang:
            continue
        langs[lang] += 1
        text = read_text(path)
        if text is None:
            continue
        test = is_test_path(rel)
        lines = text.splitlines()
        if "vigia:ignore-file" in text[:2000]:
            ignored_files.append(rel)  # explicit, reported opt-out (rule catalogues, intentional scanner code)
            routes.extend(extract_routes(rel, text, lang, lines))
            continue
        for rule in RULES:
            if lang not in rule.langs:
                continue
            for m in rule.pattern.finditer(text):
                if per_rule[rule.id] >= 200:
                    break
                line_no = text.count("\n", 0, m.start()) + 1
                line = lines[line_no - 1] if line_no - 1 < len(lines) else ""
                if line.lstrip().startswith(("#", "//", "*", "/*", "<!--")) or "nosec" in line or "vigia:ignore" in line:
                    continue
                if rule.exclude and rule.exclude.search(line):
                    continue
                around = "\n".join(lines[max(0, line_no - 4): line_no + 1])
                tainted = bool(TAINT.get(lang) and TAINT[lang].search(around))
                if rule.require_taint and not tainted:
                    continue
                conf = rule.always or ("likely" if tainted else "suspected")
                if test:
                    conf = "suspected"
                per_rule[rule.id] += 1
                drafts.append(FindingDraft(
                    title=f"{rule.title} ({rel}:{line_no})", category=rule.category, module="sast", confidence=conf,
                    native_evidence=False, asset=rel, file=rel, line=line_no, function=_enclosing(lines, line_no, lang),
                    snippet="\n".join(lines[max(0, line_no - 3): line_no + 2])[:1200],
                    description=f"Regla {rule.id}: {rule.title}." + (" La línea usa datos de entrada del usuario."
                                                                     if tainted else "") +
                                (" Fichero de pruebas/ejemplos." if test else ""),
                    evidence={"regla": rule.id, "lenguaje": lang, "entrada_usuario_cercana": tainted},
                    tags=["test-code"] if test else [], sources=["native:sast"], fingerprint_extra=rule.id))
        if lang == "python":
            drafts.extend(PythonAnalyzer(rel, text).run())
        routes.extend(extract_routes(rel, text, lang, lines))
    return drafts, routes, langs


def _enclosing(lines: list[str], line_no: int, lang: str) -> str | None:
    rx = {"python": r"^\s*(?:async\s+)?def\s+(\w+)|^\s*class\s+(\w+)",
          "javascript": r"function\s+(\w+)|(\w+)\s*[:=]\s*(?:async\s*)?(?:function|\([^)]*\)\s*=>)",
          "typescript": r"function\s+(\w+)|(\w+)\s*[:=]\s*(?:async\s*)?(?:function|\([^)]*\)\s*=>)|^\s*(?:public|private)?\s*"
                        r"(?:async\s+)?(\w+)\s*\(",
          "php": r"function\s+(\w+)", "java": r"(?:public|private|protected)[\w<>\[\]\s]+\s(\w+)\s*\(",
          "csharp": r"(?:public|private|protected|internal)[\w<>\[\]\s]+\s(\w+)\s*\(", "go": r"^func\s+(?:\([^)]*\)\s*)?(\w+)",
          "ruby": r"^\s*def\s+(\w+)"}.get(lang)
    if not rx:
        return None
    pat = re.compile(rx)
    for i in range(line_no - 1, max(-1, line_no - 200), -1):
        m = pat.search(lines[i]) if i < len(lines) else None
        if m:
            return next((g for g in m.groups() if g), None)
    return None


def extract_routes(rel: str, text: str, lang: str, lines: list[str]) -> list[dict]:
    out = []
    for plang, fw, rx in ROUTE_PATTERNS:
        if plang != lang and not (plang == "javascript" and lang == "typescript"):
            continue
        for m in rx.finditer(text):
            groups = [g for g in m.groups()]
            if fw == "django":
                path, handler, method = "/" + groups[1].lstrip("^").rstrip("$"), groups[2], "ANY"
            elif fw == "flask/fastapi":
                verb, path = groups[0], groups[1]
                method = "GET" if verb == "route" and not groups[2] else (verb.upper() if verb not in ("route", "api_route")
                                                                         else re.sub(r"[\"'\s]", "", groups[2] or "GET")
                                                                         .split(",")[0].upper())
                handler = None
            elif fw == "express/nest":
                verb = groups[0] or groups[2]
                path = groups[1] if groups[1] is not None else "/" + (groups[3] or "").lstrip("/")
                method, handler = (verb or "GET").upper(), None
            else:
                verb, path = groups[0], groups[1]
                method = (verb or "ANY").upper() if verb and verb.lower() not in ("request", "route", "handlefunc", "handle",
                                                                                  "use", "match", "any", "all") else "ANY"
                handler = None
            if path is None or len(path) > 300:
                continue
            line_no = text.count("\n", 0, m.start()) + 1
            ctx_lines = "\n".join(lines[max(0, line_no - 6): line_no + 6])
            auth = bool(AUTH_HINT.search(ctx_lines))
            out.append({"method": "GET" if method in ("USE",) else method, "path": path if path.startswith("/") else "/" + path,
                        "file": rel, "line": line_no, "auth": auth, "framework": fw,
                        "handler": handler or _handler_after(lines, line_no, lang)})
    return out


def _handler_after(lines: list[str], line_no: int, lang: str) -> str | None:
    for i in range(line_no - 1, min(len(lines), line_no + 6)):
        m = re.search(r"(?:def|function|func)\s+(\w+)|public\s+[\w<>]+\s+(\w+)\s*\(", lines[i])
        if m:
            return m.group(1) or m.group(2)
    return None


# ---------------------------------------------------------------------- Python AST taint analysis
SOURCES_ATTR = re.compile(r"^request\.(args|form|values|json|data|files|GET|POST|body|query_params|cookies|headers|path_params)")
SINKS = {
    "subprocess.call": "sast_cmdi", "subprocess.run": "sast_cmdi", "subprocess.Popen": "sast_cmdi",
    "subprocess.check_output": "sast_cmdi", "subprocess.check_call": "sast_cmdi", "os.system": "sast_cmdi",
    "os.popen": "sast_cmdi", "eval": "sast_code_injection", "exec": "sast_code_injection",
    "pickle.loads": "sast_deserialization", "yaml.load": "sast_deserialization", "open": "sast_path_traversal",
    "send_file": "sast_path_traversal", "requests.get": "sast_ssrf", "requests.post": "sast_ssrf",
    "requests.request": "sast_ssrf", "httpx.get": "sast_ssrf", "urllib.request.urlopen": "sast_ssrf",
    "urlopen": "sast_ssrf", "redirect": "sast_open_redirect", "render_template_string": "sast_template_injection",
    "Markup": "sast_xss", "mark_safe": "sast_xss",
}
SQL_METHODS = {"execute", "executemany", "raw", "extra", "executescript"}


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_name(node.value)}.{node.attr}"
    if isinstance(node, ast.Call):
        return _name(node.func)
    if isinstance(node, ast.Subscript):
        return _name(node.value)
    return ""


class PythonAnalyzer(ast.NodeVisitor):
    def __init__(self, rel: str, text: str):
        self.rel = rel
        self.text = text
        self.lines = text.splitlines()
        self.out: list[FindingDraft] = []
        self.tainted: list[set[str]] = [set()]

    def run(self) -> list[FindingDraft]:
        try:
            tree = ast.parse(self.text)
        except (SyntaxError, ValueError, RecursionError):
            return []
        self.visit(tree)
        return self.out

    def _is_tainted(self, node: ast.AST) -> bool:
        for sub in ast.walk(node):
            n = _name(sub)
            if n and (SOURCES_ATTR.match(n) or n in ("input", "sys.argv")):
                return True
            if isinstance(sub, ast.Name) and sub.id in self.tainted[-1]:
                return True
        return False

    @staticmethod
    def _dynamic_str(node: ast.AST) -> bool:
        return isinstance(node, ast.JoinedStr) or (isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod))) \
            or (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format")

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        scope = set()
        is_route = any("route" in _name(d) or _name(d).split(".")[-1] in ("get", "post", "put", "delete", "patch")
                       for d in node.decorator_list)
        if is_route:  # path/query parameters of web handlers are user input
            scope.update(a.arg for a in node.args.args if a.arg not in ("self", "request", "db", "session"))
        self.tainted.append(scope)
        self.generic_visit(node)
        self.tainted.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        if self._is_tainted(node.value):
            for t in node.targets:
                for sub in ast.walk(t):
                    if isinstance(sub, ast.Name):
                        self.tainted[-1].add(sub.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        fname = _name(node.func)
        short = fname.split(".")[-1]
        args = list(node.args) + [k.value for k in node.keywords]
        tainted_args = [a for a in args if self._is_tainted(a)]
        cat = SINKS.get(fname) or (SINKS.get(short) if short in ("redirect", "render_template_string", "send_file", "urlopen",
                                                                 "mark_safe", "Markup") else None)
        arg0 = node.args[0] if node.args else None
        sql_builder = isinstance(arg0, ast.Call) and _name(arg0.func).split(".")[-1] in (
            "select", "insert", "update", "delete", "where", "values", "order_by", "limit", "filter", "join")
        if isinstance(arg0, ast.Call) and _name(arg0.func).split(".")[-1] == "text":
            arg0 = arg0.args[0] if arg0.args else None  # text("...") is only unsafe when the string is built
        if short in SQL_METHODS and arg0 is not None and not sql_builder and (
                self._dynamic_str(arg0) or (isinstance(arg0, ast.Name) and arg0.id in self.tainted[-1])):
            cat = "sast_sqli"
            tainted_args = [arg0] if self._is_tainted(arg0) else []
            self._emit(node, cat, f"Consulta SQL dinámica en {short}()", bool(tainted_args))
        elif cat and tainted_args:
            if cat == "sast_cmdi" and fname.startswith("subprocess") and not any(
                    k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                if not isinstance(node.args[0] if node.args else None, (ast.JoinedStr, ast.BinOp)):
                    cat = None  # list argv without shell: not a shell injection
            if cat:
                self._emit(node, cat, f"Dato de entrada del usuario llega a {fname}()", True)
        self.generic_visit(node)

    def _emit(self, node: ast.Call, cat: str, title: str, tainted: bool) -> None:
        ln = getattr(node, "lineno", 1)
        self.out.append(FindingDraft(
            title=f"{title} ({self.rel}:{ln})", category=cat, module="sast", confidence="likely" if tainted else "suspected",
            native_evidence=False, asset=self.rel, file=self.rel, line=ln, function=_enclosing(self.lines, ln, "python"),
            snippet="\n".join(self.lines[max(0, ln - 3): ln + 2])[:1200],
            description="Análisis AST con seguimiento de datos dentro de la función" +
                        (": el valor procede de la petición o de la entrada." if tainted else ": cadena construida dinámicamente."),
            evidence={"motor": "ast-python", "sumidero": _name(node.func), "flujo_desde_entrada": tainted},
            sources=["native:sast-ast"], fingerprint_extra=f"ast:{_name(node.func)}"))
