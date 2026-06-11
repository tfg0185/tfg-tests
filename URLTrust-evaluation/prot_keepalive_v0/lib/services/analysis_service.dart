import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../models/analysis_finding.dart';
import '../models/analysis_result.dart';
import 'url_analysis_service.dart';

///Servicio encargado de analizar URLs y generar los resultados explicativos
///Devuelve un [AnalysisResult] con la URL analizada, puntuación, nivel
/// de riesgo y lista de hallazgos detectados.
class AnalysisService implements UrlAnalysisService {
  AnalysisService({bool enableLiveChecks = true, Uri? rdapBaseUri})
    : _enableLiveChecks = enableLiveChecks,
      _rdapBaseUri = rdapBaseUri ?? Uri.https('rdap.org');

  ///Puntuación máxima de referencia para el cálculo final
  static const int scoreCap = 32;

  ///Número máximo de redirecciones
  static const int _maxRedirects = 5;

  ///Máximo de HTML descargado permitido
  static const int _maxHtmlBytes = 30000;

  static const Duration _connectionTimeout = Duration(seconds: 15);
  static const Duration _requestTimeout = Duration(seconds: 15);
  static const Duration _responseTimeout = Duration(seconds: 6);
  static const Duration _streamReadTimeout = Duration(seconds: 6);
  static const int _maxRdapBytes = 20000;
  static const String _userAgent = 'UTrust-TFG';

  ///Permite desactivar las comprobaciones de red en tests unitarios,
  ///para probar las reglas locales sin depender de Internet.
  final bool _enableLiveChecks;

  ///Endpoint base usado para consultar RDAP.
  ///En producción usa rdap.org y en tests puede apuntar a un servidor local falso.
  final Uri _rdapBaseUri;

  ///Analiza una URL y devuelve su nivel de riesgo junto con las reglas activadas
  @override
  Future<AnalysisResult> analyzeUrl(String inputUrl) async {
    // Entrada original del usuario
    final originalInput = inputUrl.trim();
    // Validación que evita entradas que no son URL válidas
    if (!_looksLikeUrl(originalInput)) {
      return _buildInvalidResult(originalInput);
    }
    //Normalización de la URL (solo para parsing, no se analiza)
    // ex.com --> https://ex.com
    final normalizedUrl = _normalizeUrl(originalInput);
    //Parseo de la URL para extraer el dominio (host)
    final uri = _parseUri(normalizedUrl);
    //Extrae el host
    // https://ex.com/login --> ex.com
    final host = uri?.host.toLowerCase() ?? '';

    //Lista de resultados encontrados del análisis mediante heurística
    final findings = <AnalysisFinding>[
      ..._checkBasicUrlStructure(originalInput),
      ..._checkDomainStructure(host),
      ..._checkRedirectPatterns(originalInput),
      ..._checkScriptPatterns(originalInput),
      ..._checkBrandSimilarity(host),
    ];
    var dynamicHtmlStatus = 'not_requested';
    var dynamicAnalysisPartial = false;

    //Tras el uso de las reglas locales, añadimos un análisis activo
    if (_enableLiveChecks) {
      final liveResult = await _checkLiveUrlContext(uri);
      findings.addAll(liveResult.findings);
      dynamicHtmlStatus = liveResult.htmlStatus;
      dynamicAnalysisPartial = liveResult.isPartial;
    }

    return _buildResult(
      originalInput,
      findings,
      dynamicHtmlStatus: dynamicHtmlStatus,
      dynamicAnalysisPartial: dynamicAnalysisPartial,
    );
  }

  /// ─────────────────────────────────────────────
  /// Funciones auxiliares
  /// ─────────────────────────────────────────────

  ///Función auxiliar: Parseo seguro de URL
  ///Devuelve un [Uri] si el texto se puede parsear correctamente o
  ///null si falla
  Uri? _parseUri(String url) {
    try {
      return Uri.parse(url);
    } catch (_) {
      return null;
    }
  }

  /// Función auxiliar: Validación ligera de si se trata de una URL
  /// Devuelve `true` si contiene protocolo o al menos un punto y no tiene espacios o
  /// `false` si está vacía, contiene espacios o no parece una URL.
  bool _looksLikeUrl(String input) {
    final value = input.trim().toLowerCase();

    if (value.isEmpty || value.contains(' ')) return false;

    return value.startsWith('http://') ||
        value.startsWith('https://') ||
        value.contains('.');
  }

  /// Función auxiliar: Normalización de la URL (utilizada una vez ya se comprobó que es válida)
  /// Devuelve la misma entrada si contiene 'http://' o 'https://' o
  /// la entrada precedida por `https://` si no.
  String _normalizeUrl(String input) {
    if (input.startsWith('http://') || input.startsWith('https://')) {
      return input;
    }
    return 'https://$input';
  }

  ///Función auxiliar: Devuelve un mensaje de error si el enlace introducido es inválido
  ///Devuelve un [AnalysisResult] con riesgo `INVALID`, puntuación 0 y
  ///  una explicación indicando que el valor no parece una URL.
  AnalysisResult _buildInvalidResult(String input) {
    return AnalysisResult(
      url: input,
      score: 0,
      maxScore: scoreCap,
      riskLevel: 'INVALID',
      findings: [
        const AnalysisFinding(
          ruleId: 'invalid_input',
          title: 'Entrada no válida',
          explanation: 'El texto no parece un enlace.',
          recommendation:
              'Introduce un enlace válido o escanea un código QR que contenga una URL.',
          score: 0,
        ),
      ],
    );
  }

  /// ─────────────────────────────────────────────
  /// Reglas heurísticas sobre la URL
  /// ─────────────────────────────────────────────
  ///
  /// Función análisis heurístico: Detecta parámetros que puedan indicar redirecciones
  /// Devuelve una lista de [AnalysisFinding] si encuentra los parámetros analizados o
  /// una lista vacía si no se detecta ningún indicador.
  List<AnalysisFinding> _checkBasicUrlStructure(String url) {
    //Lista para guardar las alertas
    final findings = <AnalysisFinding>[];
    final lowerUrl = url.toLowerCase();

    //Analisis del uso de https
    // No penaliza: solo informa si el usuario/QR no incluye http:// o https://.
    if (!lowerUrl.startsWith('http://') && !lowerUrl.startsWith('https://')) {
      findings.add(
        const AnalysisFinding(
          ruleId: 'missing_scheme',
          title: 'El enlace no especifica protocolo',
          explanation:
              'El enlace no indica claramente si empieza por HTTP o HTTPS al inicio. HTTP envía tus datos de manera visible mientras que HTTPS los cifra para hacerlos más seguros.',
          recommendation:
              'Evita introducir contraseñas, datos bancarios o información personal en páginas sin HTTPS (https://dominio.com). Se precavido con los dominios que comienzan por HTTP (http://dominio.com).',
          score: 0,
        ),
      );
    }
    if (lowerUrl.startsWith('http://')) {
      findings.add(
        const AnalysisFinding(
          ruleId: 'insecure_http',
          title: 'La conexión puede no ir protegida',
          explanation:
              'HTTP no protege igual que HTTPS lo que envías a una página. Si una web pide contraseñas, pagos o datos personales, debería usar HTTPS.',
          recommendation:
              'Evita introducir contraseñas, datos bancarios o información personal en páginas sin HTTPS.',
          score: 2,
        ),
      );
    }
    //Análisis del uso de una URL larga (señal secundaria)
    if (url.length > 120) {
      findings.add(
        const AnalysisFinding(
          ruleId: 'very_long_url',
          title: 'Enlace muy largo',
          explanation:
              'La URL es más larga de lo habitual. Esto puede dificultar la visualización del destino real.',
          recommendation:
              'Comprueba que el enlace procede de una fuente confiable antes de acceder y busca la dirección principal en el enlace antes de abrirlo.',
          score: 2,
        ),
      );
    } else if (url.length > 75) {
      findings.add(
        const AnalysisFinding(
          ruleId: 'long_url',
          title: 'URL larga',
          explanation:
              'La URL es más larga de lo habitual. Esto puede dificultar la visualización del destino real.',
          recommendation:
              'Comprueba que el enlace procede de una fuente confiable antes de acceder y busca la dirección principal en el enlace antes de abrirlo.',
          score: 1,
        ),
      );
    }
    //Análisis del uso de '@', usado para que el navegador interprete como destino solo lo que aparece despues del @ (señal fuerte)
    if (url.contains('@')) {
      findings.add(
        const AnalysisFinding(
          ruleId: 'at_symbol',
          title: 'Símbolo @ detectado',
          explanation:
              'El enlace contiene @, un carácter que puede ocultar la web real.',
          recommendation:
              'Revisa lo que aparece después de @ antes de abrirlo o introducir datos.',
          score: 3,
        ),
      );
    }

    //Lista de palabras sospechosas en un enlace
    final suspiciousWords = [
      'login',
      'verify',
      'secure',
      'account',
      'update',
      'bank',
      'password',
      'confirm',
      'wallet',
      'payment',
    ];
    final detectedWords = suspiciousWords
        .where((word) => lowerUrl.contains(word))
        .toList();
    //Análisis del uso de palabras sospechosas (señal secundaria)
    if (detectedWords.isNotEmpty) {
      findings.add(
        AnalysisFinding(
          ruleId: 'suspicious_keywords',
          title: 'Palabras sensibles detectadas en el enlace',
          explanation:
              'Aparecen palabras relacionadas con procesos deacceso o pago. Esto por si solo no es concluyente, pero revisa el dominio y que proviene de una fuente fiable antes de introducir ningún dato sensible. Términos sospechosos: ${detectedWords.join(', ')}.',
          recommendation:
              'No introduzcas credenciales si no estás seguro de que el sitio es legítimo.',
          score: 1,
        ),
      );
    }
    return findings;
  }

  /// Función análisis heurístico: Análisis de la IP, dominio, Punycode,
  /// acortadores, subdominios, guiones y TLDs poco habituales.
  /// Devuelve una lista de [AnalysisFinding] con los indicadores detectados o
  /// una lista vacía si el dominio está vacío o no se activa ninguna regla.)

  List<AnalysisFinding> _checkDomainStructure(String host) {
    if (host.isEmpty) return [];
    //Lista para guardar las alertas
    final findings = <AnalysisFinding>[];
    //Detección de si el dominio es una IP (señal fuerte)
    final ipPattern = RegExp(r'^(\d{1,3}\.){3}\d{1,3}$');
    if (ipPattern.hasMatch(host)) {
      findings.add(
        const AnalysisFinding(
          ruleId: 'ip_as_domain',
          title: 'La web usa números en vez de un nombre',
          explanation:
              'El enlace utiliza una dirección numérica llamada dirección IP (192.15.23.00), en lugar de un nombre de dominio (https://ejemplo.com).',
          recommendation:
              'Desconfía de enlaces que usen direcciones IP, especialmente si solicitan credenciales o pagos.',
          score: 3,
        ),
      );
    }
    //Detección de dominios Punycode (señal secundaria)
    if (host.startsWith('xn--') || host.contains('.xn--')) {
      findings.add(
        const AnalysisFinding(
          ruleId: 'punycode_domain',
          title: 'Nombre de web poco habitual',
          explanation:
              'El nombre de la web usa caracteres codificados que pueden parecerse a otra dirección.',
          recommendation:
              'Comprueba la dirección con calma y evita introducir datos si no reconoces la web.',
          score: 2,
        ),
      );
    }

    //acortadores
    final shorteners = [
      'bit.ly',
      'tinyurl.com',
      't.co',
      'goo.gl',
      'is.gd',
      'ow.ly',
      'buff.ly',
      'cutt.ly',
      'shorturl.at',
    ];
    //Detección de acortadores de URL (señal fuerte)
    if (shorteners.any(
      (shortener) => host == shortener || host.endsWith('.$shortener'),
    )) {
      findings.add(
        const AnalysisFinding(
          ruleId: 'url_shortener',
          title: 'Enlace acortado',
          explanation:
              'El enlace usa un acortador, así que no muestra la web final a simple vista.',
          recommendation:
              'Ábrelo solo si confías en quien lo envió o puedes comprobar el destino.',
          score: 2,
        ),
      );
    }

    //Detección de muchos subdominios (señal secundaria)
    if (host.split('.').length > 4) {
      findings.add(
        const AnalysisFinding(
          ruleId: 'many_subdomains',
          title: 'Dirección muy partida',
          explanation:
              'La dirección tiene muchas partes antes de la web principal.',
          recommendation:
              'Fíjate especialmente en las últimas partes de la URL antes de abrirla.',
          score: 1,
        ),
      );
    }

    //Detección de varios guiones (señal secundaria)
    if ('-'.allMatches(host).length >= 3) {
      findings.add(
        const AnalysisFinding(
          ruleId: 'many_hyphens',
          title: 'Muchos guiones en el nombre',
          explanation:
              'El enlace contiene varios guiones, una técnica que puede usarse para crear dominios confusos. Eso no significa que una web legítima no pueda contener muchos guiones',
          recommendation:
              'Revisa con atención que el dominio no intenta imitar el nombre de una marca conocida.',
          score: 1,
        ),
      );
    }

    //Detección de TDL sospechosos en una URL (señal secundaria)
    final suspiciousTlds = [
      '.xyz',
      '.top',
      '.click',
      '.work',
      '.zip',
      '.cfd',
      '.country',
      '.stream',
      '.gq',
      '.tk',
    ];

    if (suspiciousTlds.any((tld) => host.endsWith(tld))) {
      findings.add(
        const AnalysisFinding(
          ruleId: 'suspicious_tld',
          title: 'Terminación poco habitual',
          explanation:
              'El dominio utiliza una extensión poco habitual (diferente a .com, .org, etc.).',
          recommendation:
              'No implica necesariamente que sea malicioso, pero conviene revisarlo con más atención.',
          score: 1,
        ),
      );
    }

    return findings;
  }

  //Función análisis heurístico: Detección de redirecciones (señal secundaria)
  List<AnalysisFinding> _checkRedirectPatterns(String url) {
    final lower = url.toLowerCase();

    final params = ['redirect=', 'url=', 'next=', 'continue='];

    if (params.any((p) => lower.contains(p))) {
      return [
        const AnalysisFinding(
          ruleId: 'redirect',
          title: 'Puede redirigir a otra web',
          explanation:
              'El enlace incluye señales de que podría llevarte a otra web.',
          recommendation:
              'Revisa la dirección final si el enlace venía de un QR o mensaje inesperado.',
          score: 2,
        ),
      ];
    }

    return [];
  }

  ///Función análisis heurístico: Análisis de patrones de scripting dentro de la URL (señal fuerte)
  List<AnalysisFinding> _checkScriptPatterns(String url) {
    String decoded;
    //Excepción si URL no se puede decodificar
    try {
      decoded = Uri.decodeFull(url).toLowerCase();
    } catch (_) {
      decoded = url.toLowerCase();
    }

    final patterns = [
      'javascript:',
      '<script',
      '%3cscript',
      'onerror=',
      'onclick=',
      'eval(',
      'document.cookie',
      'window.location',
    ];
    final detected = patterns.where((p) => decoded.contains(p)).toList();

    if (detected.isNotEmpty) {
      return [
        AnalysisFinding(
          ruleId: 'script',
          title: 'Patrones raros en el enlace',
          explanation:
              'El enlace contiene instrucciones o símbolos poco habituales. Parte sospechosa: ${detected.join(', ')}',
          recommendation:
              'Evita abrirla si procede de una fuente no verificada.',
          score: 3,
        ),
      ];
    }
    return [];
  }

  //Función análisis heurístico: detección de parecido con sitios reconocidos (señal fuerte si la distancia de Levenshtein es 1 o 0, señal secundaria si es 2)
  List<AnalysisFinding> _checkBrandSimilarity(String host) {
    if (host.isEmpty) return [];
    final findings = <AnalysisFinding>[];
    final domain = _extractDomain(host);

    final brands = [
      'paypal',
      'google',
      'amazon',
      'apple',
      'facebook',
      'microsoft',
      'netflix',
      'twitter',
      'instagram',
      'linkedin',
    ];

    for (final brand in brands) {
      final distance = _levenshtein(domain, brand);

      if (distance > 0 && distance <= 1) {
        //(distance == 1)
        findings.add(
          AnalysisFinding(
            ruleId: 'brand_similarity',
            title: 'Nombre parecido a  una marca',
            explanation: '"$domain" se parece mucho a "$brand".',
            recommendation:
                'Revisa letra por letra si esperabas entrar en una web oficial.',
            score: 3,
          ),
        );
      } else if (distance == 2) {
        findings.add(
          AnalysisFinding(
            ruleId: 'brand_similarity_secondary',
            title: 'Dominio parecido a una marca reconocida',
            explanation: '"$domain" se parece parcialmente a "$brand".',
            recommendation:
                'Revisa letra por letra si esperabas entrar en una web oficial.',
            score: 2,
          ),
        );
      }
    }
    return findings;
  }

  // ─────────────────────────────────────────────
  // Análisis de dominio
  // ─────────────────────────────────────────────
  //Función: ANÁLISIS ACTIVO. Intento de conexión con el enlace para comprobar su reputación y autenticidad
  Future<_LiveAnalysisResult> _checkLiveUrlContext(Uri? initialUri) async {
    if (initialUri == null || initialUri.host.isEmpty) {
      return const _LiveAnalysisResult(
        findings: [],
        htmlStatus: 'html_unavailable',
        isPartial: true,
      );
    }
    if (initialUri.scheme != 'http' && initialUri.scheme != 'https') {
      return const _LiveAnalysisResult(
        findings: [],
        htmlStatus: 'html_unavailable',
        isPartial: true,
      );
    }

    final findings = <AnalysisFinding>[];

    ///Esperamos a que encuentre el dominio final y despues continuamos
    final redirectResult = await _resolveRedirectChain(initialUri);
    //Detección de un problema con el certificado
    if (redirectResult.certificateProblem) {
      findings.add(
        const AnalysisFinding(
          ruleId: 'certificate_problem',
          title: 'Problema con la conexión segura',
          explanation:
              'No se pudo establecer una conexión segura válida con el sitio. HTTP no protege igual que HTTPS lo que envías a una página.',
          recommendation:
              'No introduzcas datos personales o credenciales en esta página.',
          score: 3,
        ),
      );
      return _LiveAnalysisResult(
        findings: findings,
        htmlStatus: 'html_unavailable_certificate_problem',
        isPartial: true,
      );
    }
    //Detección de acceso a la URL
    if (!redirectResult.wasReachable) {
      findings.add(
        const AnalysisFinding(
          ruleId: 'unreachable_url',
          title: 'No se pudo comprobar la web',
          explanation:
              'La aplicación no pudo conectar con el enlace para revisar el contenido.',
          recommendation:
              'Trata el resultado como una evaluación parcial y revisa el enlace con cautela.',
          score: 1,
        ),
      );
      return _LiveAnalysisResult(
        findings: findings,
        htmlStatus: 'html_unavailable',
        isPartial: true,
      );
    }

    // Comprueba el protocolo real del destino final tras resolver el enlace.
    if (redirectResult.finalUri.scheme == 'http') {
      findings.add(
        const AnalysisFinding(
          ruleId: 'final_http',
          title: 'El destino final usa HTTP',
          explanation:
              'Tras resolver el enlace, el destino final utiliza HTTP en lugar de HTTPS. Esto quiere decir que cualquier información enviada no se cifra.',
          recommendation:
              'Evita introducir datos personales, contraseñas o información bancaria en páginas sin HTTPS.',
          score: 2,
        ),
      );
    }
    //Detección de muchas redirecciones
    if (redirectResult.redirectLoop) {
      findings.add(
        const AnalysisFinding(
          ruleId: 'redirect_loop',
          title: 'Bucle de redirección detectado',
          explanation:
              'El enlace vuelve a una URL ya visitada durante la comprobación.',
          recommendation:
              'Evita acceder si el enlace procede de un QR o mensaje no verificado.',
          score: 2,
        ),
      );
    }

    if (redirectResult.tooManyRedirects) {
      findings.add(
        const AnalysisFinding(
          ruleId: 'too_many_redirects',
          title: 'Demasiados saltos',
          explanation:
              'El enlace pasa por demasiadas páginas antes de llegar al destino final.',
          recommendation:
              'Evita acceder si el enlace procede de un QR o mensaje no verificado.',
          score: 2,
        ),
      );
    }

    if (redirectResult.chain.length > 1) {
      final firstHost = redirectResult.chain.first.host.toLowerCase();
      final finalHost = redirectResult.finalUri.host.toLowerCase();

      if (!_hasEquivalentRedirectHost(firstHost, finalHost)) {
        findings.add(
          AnalysisFinding(
            ruleId: 'redirect_domain_change',
            title: 'Redirección a otra web',
            explanation:
                'El enlace empieza en "$firstHost" pero termina en "$finalHost".',
            recommendation:
                'Antes de continuar, comprueba que "$finalHost" es la web que esperabas.',
            score: 3,
          ),
        );
      } else {
        findings.add(
          AnalysisFinding(
            ruleId: 'redirect_chain',
            title: 'Redirección detectada',
            explanation:
                'El enlace realiza ${redirectResult.chain.length - 1} redirección(es) antes de mostrar el contenido.',
            recommendation:
                'Revisa el dominio final si el QR procede de un entorno físico o de un mensaje inesperado.',
            score: 1,
          ),
        );
      }
    }
    findings.addAll(await _checkDomainAge(redirectResult.finalUri.host));

    final htmlPreview = await _fetchHtmlPreview(redirectResult.finalUri);
    if (htmlPreview.content != null) {
      findings.addAll(
        _checkHtmlContent(htmlPreview.content!, redirectResult.finalUri),
      );
    }

    return _LiveAnalysisResult(
      findings: findings,
      htmlStatus: htmlPreview.status,
      isPartial: htmlPreview.isPartial,
    );
  }

  static bool hasEquivalentRedirectHostForTesting(
    String firstHost,
    String finalHost,
  ) {
    return _hasEquivalentRedirectHost(firstHost, finalHost);
  }

  static bool _hasEquivalentRedirectHost(String firstHost, String finalHost) {
    return _canonicalRedirectHost(firstHost) ==
        _canonicalRedirectHost(finalHost);
  }

  static String _canonicalRedirectHost(String host) {
    var normalizedHost = host.toLowerCase();

    if (normalizedHost.endsWith('.')) {
      normalizedHost = normalizedHost.substring(0, normalizedHost.length - 1);
    }

    const commonWebPrefixes = ['www', 'www1', 'www2', 'm', 'mobile', 'amp'];
    final hostParts = normalizedHost.split('.');

    if (hostParts.length > 2 && commonWebPrefixes.contains(hostParts.first)) {
      return hostParts.skip(1).join('.');
    }

    return normalizedHost;
  }

  ///Función auxiliar análisis activo: Intenta seguir la cadena de redirecciones reales
  Future<_RedirectResult> _resolveRedirectChain(Uri initialUri) async {
    final chain = <Uri>[initialUri];
    final visited = <String>{_canonicalUriForLoopDetection(initialUri)};
    var current = initialUri;

    try {
      for (var i = 0; i < _maxRedirects; i++) {
        final networkResponse = await _sendRedirectProbe(current);
        final response = networkResponse.response;
        final statusCode = response.statusCode;
        final location = response.headers.value(HttpHeaders.locationHeader);
        await _closeNetworkResponse(networkResponse);

        if (!_isRedirectStatus(statusCode) || location == null) {
          return _RedirectResult(
            chain: chain,
            finalUri: current,
            wasReachable: true,
          );
        }

        current = current.resolve(location);
        final canonicalCurrent = _canonicalUriForLoopDetection(current);
        if (visited.contains(canonicalCurrent)) {
          chain.add(current);
          return _RedirectResult(
            chain: chain,
            finalUri: current,
            wasReachable: true,
            redirectLoop: true,
          );
        }

        visited.add(canonicalCurrent);
        chain.add(current);
      }

      return _RedirectResult(
        chain: chain,
        finalUri: current,
        wasReachable: true,
        tooManyRedirects: true,
      );
    } on HandshakeException {
      return _RedirectResult(
        chain: chain,
        finalUri: current,
        certificateProblem: true,
      );
    } on TimeoutException {
      return _RedirectResult(chain: chain, finalUri: current);
    } on SocketException {
      return _RedirectResult(chain: chain, finalUri: current);
    } catch (_) {
      return _RedirectResult(chain: chain, finalUri: current);
    }
  }

  Future<_NetworkResponse> _sendRedirectProbe(Uri uri) async {
    try {
      final headResponse = await _sendRequest(uri, method: 'HEAD');
      final statusCode = headResponse.response.statusCode;
      final location = headResponse.response.headers.value(
        HttpHeaders.locationHeader,
      );

      if (statusCode != HttpStatus.forbidden &&
          statusCode != HttpStatus.methodNotAllowed &&
          (!_isRedirectStatus(statusCode) || location != null)) {
        return headResponse;
      }

      await _closeNetworkResponse(headResponse);
    } on HandshakeException {
      rethrow;
    } on TimeoutException {
      // Fallback controlado a GET: algunas webs no responden bien a HEAD.
    } on SocketException {
      // Fallback controlado a GET: algunas webs no responden bien a HEAD.
    }

    return _sendRequest(uri, method: 'GET');
  }

  Future<_NetworkResponse> _sendRequest(
    Uri uri, {
    required String method,
    String acceptHeader = 'text/html,*/*;q=0.8',
  }) async {
    final client = _createHttpClient();
    try {
      final request = await client
          .openUrl(method, uri)
          .timeout(_requestTimeout);
      request.followRedirects = false;
      request.maxRedirects = 0;
      request.cookies.clear();
      request.headers
        ..removeAll(HttpHeaders.cookieHeader)
        ..removeAll(HttpHeaders.authorizationHeader)
        ..set(HttpHeaders.acceptHeader, acceptHeader)
        ..set(HttpHeaders.acceptEncodingHeader, 'gzip, deflate');

      final response = await request.close().timeout(_responseTimeout);
      return _NetworkResponse(client: client, response: response);
    } catch (_) {
      client.close(force: true);
      rethrow;
    }
  }

  HttpClient _createHttpClient() {
    return HttpClient()
      ..connectionTimeout = _connectionTimeout
      ..idleTimeout = _connectionTimeout
      ..autoUncompress = true
      ..userAgent = _userAgent;
  }

  Future<void> _closeNetworkResponse(_NetworkResponse networkResponse) async {
    try {
      final socket = await networkResponse.response.detachSocket().timeout(
        _responseTimeout,
      );
      socket.destroy();
    } catch (_) {
      try {
        await networkResponse.response.drain<void>().timeout(
          const Duration(milliseconds: 500),
          onTimeout: () {},
        );
      } catch (_) {
        // El cierre forzado del cliente en finally corta cualquier conexión viva.
      }
    } finally {
      networkResponse.client.close(force: true);
    }
  }

  Future<_LimitedBytes> _readLimitedBytes(
    Stream<List<int>> stream, {
    required int maxBytes,
  }) async {
    final bytes = <int>[];

    await for (final chunk in stream) {
      final remaining = maxBytes - bytes.length;
      if (remaining <= 0) {
        return _LimitedBytes(bytes: bytes, exceededLimit: true);
      }

      if (chunk.length > remaining) {
        bytes.addAll(chunk.take(remaining));
        return _LimitedBytes(bytes: bytes, exceededLimit: true);
      }

      bytes.addAll(chunk);
    }

    return _LimitedBytes(bytes: bytes, exceededLimit: false);
  }

  String _canonicalUriForLoopDetection(Uri uri) {
    final normalized = uri.normalizePath();
    final scheme = normalized.scheme.toLowerCase();
    final host = normalized.host.toLowerCase();
    final port = normalized.hasPort ? ':${normalized.port}' : '';
    return '$scheme://$host$port${normalized.path}?${normalized.query}';
  }

  bool _isRedirectStatus(int statusCode) {
    return statusCode == HttpStatus.movedPermanently ||
        statusCode == HttpStatus.found ||
        statusCode == HttpStatus.movedTemporarily ||
        statusCode == HttpStatus.seeOther ||
        statusCode == HttpStatus.temporaryRedirect ||
        statusCode == HttpStatus.permanentRedirect;
  }

  ///Obtención de la antigüedad del dominio
  Future<List<AnalysisFinding>> _checkDomainAge(String host) async {
    if (_isIpAddress(host)) return [];
    //Dominio principal registrable (quitamos subdominios)
    final domain = _extractRegistrableDomain(host);
    if (domain.isEmpty || _isIpAddress(domain)) return [];

    try {
      //Construccióni de la URL de consulta
      final uri = _rdapBaseUri.resolve('/domain/$domain');
      final networkResponse = await _sendRequest(
        uri,
        method: 'GET',
        acceptHeader: 'application/rdap+json',
      );
      final response = networkResponse.response;
      //Cuando la petición no es correcta, vacía la respuesta y no devuelve nada
      if (response.statusCode != HttpStatus.ok) {
        await _closeNetworkResponse(networkResponse);
        return [];
      }
      //Se transforma de bytes a texto
      late final _LimitedBytes limitedBody;
      try {
        limitedBody = await _readLimitedBytes(
          response,
          maxBytes: _maxRdapBytes,
        ).timeout(_streamReadTimeout);
      } finally {
        networkResponse.client.close(force: true);
      }

      if (limitedBody.exceededLimit) return [];

      final body = utf8.decode(limitedBody.bytes, allowMalformed: true);
      //Convierte el texto JSON en un objeto de Dart
      final data = jsonDecode(body);

      if (data is! Map<String, dynamic>) return [];

      final events = data['events'];
      if (events is! List) return [];

      DateTime? registrationDate;
      //Recorre todos los eventos RDAP (los eventos RDAP son fechas importantes relacionadas con el dominio)
      for (final event in events) {
        if (event is! Map<String, dynamic>) continue;
        //Lectura del tipo de evento
        final action = event['eventAction']?.toString().toLowerCase() ?? '';
        //Lectura fecha del evento
        final dateValue = event['eventDate']?.toString();
        //Si el evento no es de registro, o no tiene fecha, lo salta.
        if (!action.contains('registration') || dateValue == null) continue;
        registrationDate = DateTime.tryParse(dateValue);
        if (registrationDate != null) break;
      }

      if (registrationDate == null) return [];
      //Calcula cuántos días han pasado desde que se registró el dominio.
      final age = DateTime.now().difference(registrationDate).inDays;
      if (age < 30) {
        return [
          AnalysisFinding(
            ruleId: 'very_new_domain',
            title: 'Dominio creado recientemente',
            explanation:
                '"$domain" parece haberse creado hace menos de 30 días.',
            recommendation:
                'Ten especial cuidado si solicita contraseñas, pagos o datos personales.',
            score: 3,
          ),
        ];
      }

      if (age < 180) {
        return [
          AnalysisFinding(
            ruleId: 'new_domain',
            title: 'Dominio relativamente nuevo',
            explanation:
                '"$domain" parece haberse creado hace menos de seis meses.',
            recommendation:
                'Revísala con más atención si pide datos personales o pagos.',
            score: 1,
          ),
        ];
      }
    } catch (_) {
      return [];
    }

    return [];
  }

  ///Método expuesto únicamente para probar el parser RDAP sin consultar Internet.
  ///Permite validar la lógica con un servidor local controlado por los tests.
  Future<List<AnalysisFinding>> checkDomainAgeForTesting(String host) {
    return _checkDomainAge(host);
  }

  ///Descarga una muestra del HTML final
  Future<_HtmlPreview> _fetchHtmlPreview(Uri uri) async {
    if (uri.scheme != 'http' && uri.scheme != 'https') {
      return const _HtmlPreview(status: 'html_unavailable', isPartial: true);
    }

    try {
      final networkResponse = await _sendRequest(uri, method: 'GET');
      final response = networkResponse.response;
      final contentType = response.headers.contentType?.mimeType ?? '';

      if (!contentType.contains('html')) {
        await _closeNetworkResponse(networkResponse);
        return const _HtmlPreview(status: 'html_not_html');
      }

      final contentLength = response.contentLength;
      if (contentLength > _maxHtmlBytes) {
        await _closeNetworkResponse(networkResponse);
        return const _HtmlPreview(status: 'html_too_large', isPartial: true);
      }

      late final _LimitedBytes limitedHtml;
      try {
        limitedHtml = await _readLimitedBytes(
          response,
          maxBytes: _maxHtmlBytes,
        ).timeout(_streamReadTimeout);
      } finally {
        networkResponse.client.close(force: true);
      }

      if (limitedHtml.exceededLimit) {
        return const _HtmlPreview(status: 'html_too_large', isPartial: true);
      }

      return _HtmlPreview(
        content: utf8
            .decode(limitedHtml.bytes, allowMalformed: true)
            .toLowerCase(),
        status: 'html_analyzed',
      );
    } on TimeoutException {
      return const _HtmlPreview(
        status: 'html_unavailable_timeout',
        isPartial: true,
      );
    } catch (_) {
      return const _HtmlPreview(
        status: 'html_unavailable_error',
        isPartial: true,
      );
    }
  }

  ///Busca patrones de contenido sospechoso
  List<AnalysisFinding> _checkHtmlContent(String html, Uri pageUri) {
    final findings = <AnalysisFinding>[];

    final hasPasswordInput = RegExp(
      r"""<input[^>]+type=["']?password""",
      caseSensitive: false,
    ).hasMatch(html);

    if (hasPasswordInput) {
      findings.add(
        const AnalysisFinding(
          ruleId: 'password_form',
          title: 'Formulario de contraseña',
          explanation:
              'La página contiene un campo de contraseña, por lo que podría estar solicitando credenciales.',
          recommendation:
              'Antes de iniciar sesión, verifica que el dominio pertenece al servicio oficial.',
          score: 2,
        ),
      );
    }

    final sensitiveInputs = RegExp(
      r"""<input[^>]+(name|id)=["']?[^>"']*(card|cvv|dni|password|pass|email|user|account)[^>"']*""",
      caseSensitive: false,
    ).allMatches(html).length;

    if (sensitiveInputs >= 3) {
      findings.add(
        const AnalysisFinding(
          ruleId: 'many_sensitive_inputs',
          title: 'Campos sensibles en la página',
          explanation:
              'Se detectan varios campos asociados a credenciales, identidad o pagos.',
          recommendation:
              'No introduzcas información personal si no has confirmado la legitimidad del sitio.',
          score: 2,
        ),
      );
    }

    if (_hasExternalFormAction(html, pageUri)) {
      findings.add(
        const AnalysisFinding(
          ruleId: 'external_form_action',
          title: 'Formulario enviado a otro dominio',
          explanation:
              'La página contiene un formulario que podría enviar datos a otra web.',
          recommendation:
              'No envíes datos si esa web no coincide con la que esperabas.',
          score: 3,
        ),
      );
    }

    if (_hasHiddenIframe(html)) {
      findings.add(
        const AnalysisFinding(
          ruleId: 'hidden_iframe',
          title: 'Iframe oculto detectado',
          explanation:
              'La página carga un elemento oculto dentro del contenido.',
          recommendation:
              'No interactúes con la página si procede de un QR o enlace no verificado.',
          score: 2,
        ),
      );
    }

    findings.addAll(_checkPageTitleBrandMismatch(html, pageUri.host));

    return findings;
  }

  bool _hasExternalFormAction(String html, Uri pageUri) {
    final formActionPattern = RegExp(
      r"""<form[^>]+action=["']([^"']+)["']""",
      caseSensitive: false,
    );

    for (final match in formActionPattern.allMatches(html)) {
      final action = match.group(1);
      if (action == null || action.trim().isEmpty) continue;
      final actionUri = pageUri.resolve(action);
      if (actionUri.host.isNotEmpty &&
          actionUri.host.toLowerCase() != pageUri.host.toLowerCase()) {
        return true;
      }
    }

    return false;
  }

  bool _hasHiddenIframe(String html) {
    return RegExp(
      r"""<iframe[^>]+(display\s*:\s*none|visibility\s*:\s*hidden|width=["']?0|height=["']?0)""",
      caseSensitive: false,
    ).hasMatch(html);
  }

  List<AnalysisFinding> _checkPageTitleBrandMismatch(String html, String host) {
    final titleMatch = RegExp(
      r'<title[^>]*>(.*?)</title>',
      caseSensitive: false,
      dotAll: true,
    ).firstMatch(html);
    final title = titleMatch?.group(1)?.toLowerCase() ?? '';
    if (title.isEmpty) return [];

    final findings = <AnalysisFinding>[];
    final brands = ['paypal', 'google', 'amazon', 'apple', 'microsoft'];

    for (final brand in brands) {
      if (title.contains(brand) && !host.toLowerCase().contains(brand)) {
        findings.add(
          AnalysisFinding(
            ruleId: 'title_brand_mismatch',
            title: 'Marca en el título pero no en el dominio',
            explanation:
                'El título menciona "$brand", pero la web real no parece ser de esa marca.',
            recommendation:
                'Comprueba la dirección oficial antes de introducir datos.',
            score: 3,
          ),
        );
        break;
      }
    }

    return findings;
  }

  String _extractDomain(String host) {
    final parts = host.split('.');
    if (parts.length < 2) return host;
    return parts[parts.length - 2];
  }

  String _extractRegistrableDomain(String host) {
    final cleanHost = host.toLowerCase().replaceFirst(RegExp(r':\d+$'), '');
    final parts = cleanHost.split('.').where((p) => p.isNotEmpty).toList();
    if (parts.length < 2) return cleanHost;
    return '${parts[parts.length - 2]}.${parts.last}';
  }

  bool _isIpAddress(String value) {
    return RegExp(r'^(\d{1,3}\.){3}\d{1,3}$').hasMatch(value);
  }

  int _levenshtein(String a, String b) {
    final matrix = List.generate(
      a.length + 1,
      (_) => List<int>.filled(b.length + 1, 0),
    );

    for (int i = 0; i <= a.length; i++) {
      matrix[i][0] = i;
    }
    for (int j = 0; j <= b.length; j++) {
      matrix[0][j] = j;
    }

    for (int i = 1; i <= a.length; i++) {
      for (int j = 1; j <= b.length; j++) {
        final cost = a[i - 1] == b[j - 1] ? 0 : 1;

        matrix[i][j] = [
          matrix[i - 1][j] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j - 1] + cost,
        ].reduce((v, e) => v < e ? v : e);
      }
    }
    return matrix[a.length][b.length];
  }

  AnalysisResult _buildResult(
    String url,
    List<AnalysisFinding> findings, {
    String dynamicHtmlStatus = 'not_requested',
    bool dynamicAnalysisPartial = false,
  }) {
    final rawScore = findings.fold(0, (sum, f) => sum + f.score);
    final score = rawScore.clamp(0, scoreCap).toInt();

    final effectiveFindings = findings.isEmpty
        ? [
            const AnalysisFinding(
              ruleId: 'no_findings',
              title: 'Sin indicadores sospechosos',
              explanation:
                  'No se han detectado indicadores sospechosos en esta evaluación inicial.',
              recommendation:
                  'Aun así, verifica siempre que el dominio corresponde al sitio al que quieres acceder.',
              score: 0,
            ),
          ]
        : findings;

    return AnalysisResult(
      url: url,
      score: score,
      maxScore: scoreCap,
      riskLevel: _classifyRisk(score),
      findings: effectiveFindings,
      dynamicHtmlStatus: dynamicHtmlStatus,
      dynamicAnalysisPartial: dynamicAnalysisPartial,
    );
  }

  String _classifyRisk(int score) {
    if (score >= 6) return 'POTENTIALLY_MALICIOUS';
    if (score >= 3) return 'SUSPICIOUS';
    return 'LOW_RISK';
  }
}

class _RedirectResult {
  final List<Uri> chain;
  final Uri finalUri;
  final bool wasReachable;
  final bool tooManyRedirects;
  final bool certificateProblem;
  final bool redirectLoop;

  const _RedirectResult({
    required this.chain,
    required this.finalUri,
    this.wasReachable = false,
    this.tooManyRedirects = false,
    this.certificateProblem = false,
    this.redirectLoop = false,
  });
}

class _NetworkResponse {
  final HttpClient client;
  final HttpClientResponse response;

  const _NetworkResponse({required this.client, required this.response});
}

class _LimitedBytes {
  final List<int> bytes;
  final bool exceededLimit;

  const _LimitedBytes({required this.bytes, required this.exceededLimit});
}

class _HtmlPreview {
  final String? content;
  final String status;
  final bool isPartial;

  const _HtmlPreview({
    this.content,
    required this.status,
    this.isPartial = false,
  });
}

class _LiveAnalysisResult {
  final List<AnalysisFinding> findings;
  final String htmlStatus;
  final bool isPartial;

  const _LiveAnalysisResult({
    required this.findings,
    required this.htmlStatus,
    required this.isPartial,
  });
}
