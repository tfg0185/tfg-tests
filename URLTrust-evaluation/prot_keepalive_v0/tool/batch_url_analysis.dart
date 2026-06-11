import 'dart:io';

import 'package:prot_keepalive_v0/services/analysis_service.dart';
import 'package:prot_keepalive_v0/services/batch_url_analysis_service.dart';

Future<void> main(List<String> arguments) async {
  if (arguments.contains('--live')) {
    stderr.writeln(
      'El modo activo esta deshabilitado en la evaluacion por lote para evitar '
      'contactar con enlaces reales.',
    );
    exitCode = 64;
    return;
  }

  final options = _BatchCommandOptions.fromArguments(arguments);
  const benignCsvAnalysisLimit = 200;

  final batchService = BatchUrlAnalysisService(
    analysisService: AnalysisService(enableLiveChecks: true),
    benignAnalysisService: AnalysisService(enableLiveChecks: true),
    benignCsvAnalysisLimit: benignCsvAnalysisLimit,
  );

  
  final report = await batchService.analyzeFiles(
    inputFiles: options.inputPaths.map(File.new).toList(),
    outputFile: File(options.outputPath),
  );
  
  stdout.writeln('Iniciando analisis por lote...');
  stdout.writeln('Entradas: ${options.inputPaths.join(', ')}');
  stdout.writeln('Salida: ${options.outputPath}');
  stdout.writeln('Analisis dinamico en maliciosas: ACTIVADO');
  stdout.writeln('Analisis dinamico en benignas: ACTIVADO');
  stdout.writeln('Esto puede tardar si hay URLs caidas o timeouts.');
  stdout.writeln('Archivos de entrada: ${report.inputPath}');
  
  stdout.writeln('Limite CSV benigno: $benignCsvAnalysisLimit enlaces');
  stdout.writeln('URLs analizadas: ${report.urls.length}');
  stdout.writeln('CSV generado: ${report.outputPath}');

  if (report.urls.isEmpty) {
    stdout.writeln(
      'No se encontro ninguna URL. Usa un TXT con una URL por linea o un CSV '
      'Tranco con ranking y dominio.',
    );
  }
}

class _BatchCommandOptions {
  final List<String> inputPaths;
  final String outputPath;

  const _BatchCommandOptions({
    required this.inputPaths,
    required this.outputPath,
  });

  factory _BatchCommandOptions.fromArguments(List<String> arguments) {
    const defaultInputPaths = [
      'data/manual_urls.txt',
      'data/benign_url_tranco.csv',
    ];
    const defaultOutputPath = 'data/manual_url_results.csv';

    var outputPath = defaultOutputPath;
    final inputPaths = <String>[];

    for (final argument in arguments) {
      if (argument.startsWith('--output=')) {
        outputPath = argument.substring('--output='.length);
      } else {
        inputPaths.add(argument);
      }
    }

    if (inputPaths.length == 2 &&
        !arguments.any((argument) => argument.startsWith('--output=')) &&
        inputPaths.last.toLowerCase().endsWith('.csv')) {
      return _BatchCommandOptions(
        inputPaths: [inputPaths.first],
        outputPath: inputPaths.last,
      );
    }

    return _BatchCommandOptions(
      inputPaths: inputPaths.isEmpty ? defaultInputPaths : inputPaths,
      outputPath: outputPath,
    );
  }
}
