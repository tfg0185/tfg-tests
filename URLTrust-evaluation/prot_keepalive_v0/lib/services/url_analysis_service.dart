import '../models/analysis_result.dart';

abstract interface class UrlAnalysisService {
  Future<AnalysisResult> analyzeUrl(String inputUrl);
}
