import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:prot_keepalive_v0/models/analysis_finding.dart';
import 'package:prot_keepalive_v0/models/analysis_result.dart';
import 'package:prot_keepalive_v0/services/batch_url_analysis_service.dart';
import 'package:prot_keepalive_v0/services/url_analysis_service.dart';

void main() {
  group('BatchUrlAnalysisService', () {
    test(
      'extrae URLs desde texto normal ignorando comentarios y duplicados',
      () {
        final urls = BatchUrlAnalysisService.extractUrls('''
        # https://ignorada.example
        Revisar https://example.com/login.
        Tambien paypal.com y https://example.com/login
      ''');

        expect(urls, ['https://example.com/login', 'paypal.com']);
      },
    );

    test('extrae dominios desde CSV Tranco con ranking y dominio', () {
      final urls = BatchUrlAnalysisService.extractUrls('''
        rank,domain
        1,google.com
        2,gtld-servers.net
        3,"cloudflare.com"
        3,"cloudflare.com"
      ''');

      expect(urls, ['google.com', 'gtld-servers.net', 'cloudflare.com']);
    });

    test('limita el CSV benigno a los primeros 200 dominios', () async {
      final tempDir = await Directory.systemTemp.createTemp(
        'batch_url_analysis_test_',
      );
      addTearDown(() => tempDir.delete(recursive: true));

      final dataDir = Directory('${tempDir.path}/data');
      await dataDir.create();
      final inputFile = File('${dataDir.path}/benign_url_tranco.csv');
      final outputFile = File('${dataDir.path}/results.csv');
      await inputFile.writeAsString(
        List.generate(205, (index) => '${index + 1},example$index.com').join(
          '\n',
        ),
      );

      final service = BatchUrlAnalysisService(
        analysisService: _FakeAnalysisService(),
      );

      final report = await service.analyzeFile(
        inputFile: inputFile,
        outputFile: outputFile,
      );

      expect(report.urls.length, 200);
      expect(report.urls.first, 'example0.com');
      expect(report.urls.last, 'example199.com');
    });

    test('usa dinamico solo para el CSV benigno', () async {
      final tempDir = await Directory.systemTemp.createTemp(
        'batch_url_analysis_test_',
      );
      addTearDown(() => tempDir.delete(recursive: true));

      final dataDir = Directory('${tempDir.path}/data');
      await dataDir.create();
      final manualFile = File('${dataDir.path}/manual_urls.txt');
      final benignFile = File('${dataDir.path}/benign_url_tranco.csv');
      final outputFile = File('${dataDir.path}/results.csv');

      await manualFile.writeAsString('https://malicious.example');
      await benignFile.writeAsString('1,google.com');

      final service = BatchUrlAnalysisService(
        analysisService: _FakeAnalysisService(dynamicStatus: 'not_requested'),
        benignAnalysisService: _FakeAnalysisService(dynamicStatus: 'html_ok'),
      );

      final report = await service.analyzeFiles(
        inputFiles: [manualFile, benignFile],
        outputFile: outputFile,
      );

      expect(report.rows.first.dynamicHtmlStatus, 'not_requested');
      expect(report.rows.first.connectionEstablished, isFalse);
      expect(report.rows.last.dynamicHtmlStatus, 'html_ok');
      expect(report.rows.last.connectionEstablished, isTrue);
    });

    test('genera CSV con resultado, puntuacion, reglas y conexion', () async {
      final service = BatchUrlAnalysisService(
        analysisService: _FakeAnalysisService(),
      );

      final rows = await service.analyzeUrls([
        'https://ok.example',
        'https://offline.example',
      ], sourceFile: 'data/benign_url_tranco.csv');
      final csv = BatchUrlAnalysisService.buildCsv(rows);

      expect(
        csv,
        contains(
          'url,archivo_entrada,resultado_final,puntuacion,puntuacion_maxima,'
          'reglas_activadas,analisis_estatico_realizado,conexion_establecida,'
          'estado_html_dinamico,analisis_dinamico_parcial',
        ),
      );
      expect(
        csv,
        contains(
          'https://ok.example,data/benign_url_tranco.csv,LOW_RISK,0,32,'
          'no_findings,si,no,not_requested,no',
        ),
      );
      expect(
        csv,
        contains(
          'https://offline.example,data/benign_url_tranco.csv,SUSPICIOUS,3,32,'
          'insecure_http|unreachable_url,si,no,not_requested,no',
        ),
      );
    });
  });
}

class _FakeAnalysisService implements UrlAnalysisService {
  final String dynamicStatus;

  const _FakeAnalysisService({this.dynamicStatus = 'not_requested'});

  @override
  Future<AnalysisResult> analyzeUrl(String inputUrl) async {
    if (inputUrl.contains('offline')) {
      return AnalysisResult(
        url: inputUrl,
        score: 3,
        maxScore: 32,
        riskLevel: 'SUSPICIOUS',
        findings: const [
          AnalysisFinding(
            ruleId: 'insecure_http',
            title: 'HTTP',
            explanation: 'Usa HTTP.',
            recommendation: 'Revisar.',
            score: 2,
          ),
          AnalysisFinding(
            ruleId: 'unreachable_url',
            title: 'Sin conexion',
            explanation: 'No se pudo conectar.',
            recommendation: 'Evaluacion parcial.',
            score: 1,
          ),
        ],
        dynamicHtmlStatus: dynamicStatus,
        dynamicAnalysisPartial: dynamicStatus != 'not_requested',
      );
    }

    return AnalysisResult(
      url: inputUrl,
      score: 0,
      maxScore: 32,
      riskLevel: 'LOW_RISK',
      findings: const [
        AnalysisFinding(
          ruleId: 'no_findings',
          title: 'Sin indicadores',
          explanation: 'Sin indicadores sospechosos.',
          recommendation: 'Verificar dominio.',
          score: 0,
        ),
      ],
      dynamicHtmlStatus: dynamicStatus,
    );
  }
}
