import 'dart:io';

import '../models/analysis_result.dart';
import 'url_analysis_service.dart';

class BatchUrlAnalysisService {
  final UrlAnalysisService analysisService;
  final UrlAnalysisService? benignAnalysisService;
  final int benignCsvAnalysisLimit;
  final String benignCsvFileName;

  const BatchUrlAnalysisService({
    required this.analysisService,
    this.benignAnalysisService,
    this.benignCsvAnalysisLimit = 200,
    this.benignCsvFileName = 'benign_url_tranco.csv',
  });

  Future<BatchUrlAnalysisReport> analyzeFile({
    required File inputFile,
    required File outputFile,
  }) async {
    return analyzeFiles(inputFiles: [inputFile], outputFile: outputFile);
  }

  Future<BatchUrlAnalysisReport> analyzeFiles({
    required List<File> inputFiles,
    required File outputFile,
  }) async {
    final urls = <String>[];
    final rows = <BatchUrlAnalysisRow>[];

    for (final inputFile in inputFiles) {
      final inputText = await inputFile.readAsString();
      final sourceFile = _displayPath(inputFile);
      final benignCsvUrlsToAnalyze = _isBenignCsvSource(sourceFile)
          ? benignCsvAnalysisLimit
          : null;
      final fileUrls = extractUrls(inputText, limit: benignCsvUrlsToAnalyze);

      urls.addAll(fileUrls);
      rows.addAll(
        await analyzeUrls(
          fileUrls,
          sourceFile: sourceFile,
          urlAnalysisService: _analysisServiceForSource(sourceFile),
        ),
      );
    }

    final csv = buildCsv(rows);

    await outputFile.parent.create(recursive: true);
    await outputFile.writeAsString(csv);

    return BatchUrlAnalysisReport(
      inputPaths: inputFiles.map((file) => file.path).toList(),
      outputPath: outputFile.path,
      urls: urls,
      rows: rows,
    );
  }

  Future<List<BatchUrlAnalysisRow>> analyzeUrls(
  List<String> urls, {
  String sourceFile = '',
  UrlAnalysisService? urlAnalysisService,
}) async {
  final rows = <BatchUrlAnalysisRow>[];
  final selectedAnalysisService = urlAnalysisService ?? analysisService;
  final total = urls.length;

  stdout.writeln('Analizando $total URLs de $sourceFile');
  await stdout.flush();

  for (var index = 0; index < urls.length; index += 1) {
    final url = urls[index];

    stdout.writeln('[${index + 1}/$total] Analizando: $url');
    await stdout.flush();

    final stopwatch = Stopwatch()..start();

    try {
      final result = await selectedAnalysisService.analyzeUrl(url);
      stopwatch.stop();

      stdout.writeln(
        '  -> ${result.riskLevel} | score=${result.score} | '
        'reglas=${result.findings.map((finding) => finding.ruleId).join('|')} | '
        'html=${result.dynamicHtmlStatus} | '
        'parcial=${result.dynamicAnalysisPartial ? 'si' : 'no'} | '
        '${stopwatch.elapsed.inSeconds}s',
      );
      await stdout.flush();

      rows.add(BatchUrlAnalysisRow.fromResult(result, sourceFile: sourceFile));
    } catch (error) {
      stopwatch.stop();

      stderr.writeln(
        '  -> ERROR analizando $url | ${stopwatch.elapsed.inSeconds}s | $error',
      );
      await stderr.flush();

      rethrow;
    }
  }

  return rows;
}

  UrlAnalysisService _analysisServiceForSource(String sourceFile) {
    if (_isBenignCsvSource(sourceFile)) {
      return benignAnalysisService ?? analysisService;
    }

    return analysisService;
  }

  bool _isBenignCsvSource(String sourceFile) {
    return sourceFile.split('/').last == benignCsvFileName;
  }

  static List<String> extractUrls(String text, {int? limit}) {
    final urls = <String>[];
    final seen = <String>{};
    final urlPattern = RegExp(
      r'''(?:https?:\/\/)?[^\s<>"']+\.[^\s<>"']+''',
      caseSensitive: false,
    );

    for (final line in text.split(RegExp(r'\r?\n'))) {
      final trimmedLine = line.trim();
      if (trimmedLine.isEmpty || trimmedLine.startsWith('#')) continue;

      final csvUrl = _extractUrlFromCsvLine(trimmedLine);
      if (csvUrl != null) {
        if (!seen.contains(csvUrl)) {
          seen.add(csvUrl);
          urls.add(csvUrl);
          if (limit != null && urls.length >= limit) return urls;
        }
        continue;
      }

      for (final match in urlPattern.allMatches(trimmedLine)) {
        final candidate = _cleanUrlCandidate(match.group(0) ?? '');
        if (candidate.isEmpty || seen.contains(candidate)) continue;

        seen.add(candidate);
        urls.add(candidate);
        if (limit != null && urls.length >= limit) return urls;
      }
    }

    return urls;
  }

  static String? _extractUrlFromCsvLine(String line) {
    if (!line.contains(',')) return null;

    final fields = _parseCsvLine(line);
    if (fields.length < 2) return null;

    final firstField = fields.first.trim().toLowerCase();
    final secondField = fields[1].trim();
    final secondFieldLower = secondField.toLowerCase();

    final isHeader =
        (firstField == 'rank' ||
            firstField == 'ranking' ||
            firstField == 'id') &&
        (secondFieldLower == 'domain' ||
            secondFieldLower == 'dominio' ||
            secondFieldLower == 'url');
    if (isHeader) return null;

    if (int.tryParse(firstField) == null) return null;

    final candidate = _cleanUrlCandidate(secondField);
    if (candidate.isEmpty || !candidate.contains('.')) return null;

    return candidate;
  }

  static List<String> _parseCsvLine(String line) {
    final fields = <String>[];
    final current = StringBuffer();
    var inQuotes = false;

    for (var index = 0; index < line.length; index += 1) {
      final char = line[index];
      if (char == '"') {
        if (inQuotes && index + 1 < line.length && line[index + 1] == '"') {
          current.write('"');
          index += 1;
        } else {
          inQuotes = !inQuotes;
        }
      } else if (char == ',' && !inQuotes) {
        fields.add(current.toString());
        current.clear();
      } else {
        current.write(char);
      }
    }

    fields.add(current.toString());
    return fields;
  }

  static String buildCsv(List<BatchUrlAnalysisRow> rows) {
    final buffer = StringBuffer()
      ..writeln(
        [
          'url',
          'archivo_entrada',
          'resultado_final',
          'puntuacion',
          'puntuacion_maxima',
          'reglas_activadas',
          'analisis_estatico_realizado',
          'conexion_establecida',
          'estado_html_dinamico',
          'analisis_dinamico_parcial',
        ].map(_csvEscape).join(','),
      );

    for (final row in rows) {
      buffer.writeln(
        [
          row.url,
          row.sourceFile,
          row.riskLevel,
          row.score.toString(),
          row.maxScore.toString(),
          row.ruleIds.join('|'),
          row.staticAnalysisCompleted ? 'si' : 'no',
          row.connectionEstablished ? 'si' : 'no',
          row.dynamicHtmlStatus,
          row.dynamicAnalysisPartial ? 'si' : 'no',
        ].map(_csvEscape).join(','),
      );
    }

    return buffer.toString();
  }

  static String _cleanUrlCandidate(String value) {
    var cleaned = value.trim();
    cleaned = cleaned.replaceFirst(RegExp(r'^[\(\[\{<]+'), '');
    cleaned = cleaned.replaceFirst(RegExp(r'[.,;:!\?\)\]\}>]+$'), '');
    return cleaned;
  }

  static String _csvEscape(String value) {
    final escaped = value.replaceAll('"', '""');
    if (escaped.contains(',') ||
        escaped.contains('"') ||
        escaped.contains('\n') ||
        escaped.contains('\r')) {
      return '"$escaped"';
    }

    return escaped;
  }

  static String _displayPath(File file) {
    final normalized = file.path.replaceAll('\\', '/');
    final dataIndex = normalized.indexOf('data/');
    if (dataIndex >= 0) return normalized.substring(dataIndex);
    return normalized;
  }
}

class BatchUrlAnalysisReport {
  final List<String> inputPaths;
  final String outputPath;
  final List<String> urls;
  final List<BatchUrlAnalysisRow> rows;

  const BatchUrlAnalysisReport({
    required this.inputPaths,
    required this.outputPath,
    required this.urls,
    required this.rows,
  });

  String get inputPath => inputPaths.join(', ');
}

class BatchUrlAnalysisRow {
  final String url;
  final String sourceFile;
  final String riskLevel;
  final int score;
  final int maxScore;
  final List<String> ruleIds;
  final bool staticAnalysisCompleted;
  final bool connectionEstablished;
  final String dynamicHtmlStatus;
  final bool dynamicAnalysisPartial;

  const BatchUrlAnalysisRow({
    required this.url,
    required this.sourceFile,
    required this.riskLevel,
    required this.score,
    required this.maxScore,
    required this.ruleIds,
    required this.staticAnalysisCompleted,
    required this.connectionEstablished,
    required this.dynamicHtmlStatus,
    required this.dynamicAnalysisPartial,
  });

  factory BatchUrlAnalysisRow.fromResult(
    AnalysisResult result, {
    String sourceFile = '',
  }) {
    final ruleIds = result.findings.map((finding) => finding.ruleId).toList();
    final isInvalidInput = ruleIds.contains('invalid_input');
    final dynamicAnalysisRequested = result.dynamicHtmlStatus != 'not_requested';

    return BatchUrlAnalysisRow(
      url: result.url,
      sourceFile: sourceFile,
      riskLevel: result.riskLevel,
      score: result.score,
      maxScore: result.maxScore,
      ruleIds: ruleIds,
      staticAnalysisCompleted: !isInvalidInput,
      connectionEstablished:
          dynamicAnalysisRequested && !ruleIds.contains('unreachable_url'),
      dynamicHtmlStatus: result.dynamicHtmlStatus,
      dynamicAnalysisPartial: result.dynamicAnalysisPartial,
    );
  }
}
