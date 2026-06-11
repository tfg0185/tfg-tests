//Modelo de resultado
import 'analysis_finding.dart';

class AnalysisResult {
  final String url;
  final int score;
  final int maxScore;
  final String riskLevel;
  final List<AnalysisFinding> findings;
  final String dynamicHtmlStatus;
  final bool dynamicAnalysisPartial;

  AnalysisResult({
    required this.url,
    required this.score,
    required this.maxScore,
    required this.riskLevel,
    required this.findings,
    this.dynamicHtmlStatus = 'not_requested',
    this.dynamicAnalysisPartial = false,
  });

  int get riskPercentage {
    return ((score / maxScore) * 100).clamp(0, 100).round();
  }

  List<String> get reasons {
    return findings.map((finding) => finding.explanation).toList();
  }

  // Posible uso en un futuro
  /// No se muestran actualmente en la UI principal para evitar duplicidad
  List<String> get recommendations {
    return findings.map((finding) => finding.recommendation).toSet().toList();
  }
}
