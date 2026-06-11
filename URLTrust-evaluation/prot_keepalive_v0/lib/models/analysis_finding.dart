class AnalysisFinding {
  final String ruleId;
  final String title;
  final String explanation;
  final String recommendation;
  final int score;

  const AnalysisFinding({
    required this.ruleId,
    required this.title,
    required this.explanation,
    required this.recommendation,
    required this.score,
  });
}
