import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:prot_keepalive_v0/main.dart';

void main() {
  testWidgets('Home screen smoke test', (WidgetTester tester) async {
    // Prueba de humo de la interfaz inicial.
    // En el contexto del TFG, esta prueba no evalua la utilidad del detector,
    // sino que verifica que la app arranca y muestra los dos flujos principales.
    await tester.pumpWidget(const UTrustApp());

    expect(find.text('UTrust'), findsWidgets);
    expect(find.text('Escanear QR'), findsOneWidget);
    expect(find.text('Introducir URL'), findsOneWidget);
    expect(find.byTooltip('Demo guiada'), findsOneWidget);
    expect(find.widgetWithText(OutlinedButton, 'Demo guiada'), findsNothing);

    await tester.tap(find.byTooltip('Demo guiada'));
    await tester.pumpAndSettle();

    expect(find.text('¿Qué es phishing?'), findsOneWidget);
    expect(find.text('Paso 1 de 7'), findsOneWidget);

    await tester.tap(find.text('Siguiente'));
    await tester.pumpAndSettle();

    expect(find.text('¿Qué es quishing?'), findsOneWidget);
    expect(find.text('Paso 2 de 7'), findsOneWidget);

    for (var i = 0; i < 5; i++) {
      await tester.tap(find.text('Siguiente'));
      await tester.pumpAndSettle();
    }

    expect(find.text('Cómo interpretar UTrust'), findsOneWidget);
    expect(find.text('Paso 7 de 7'), findsOneWidget);
    expect(find.text('Probar con una URL'), findsOneWidget);

    await tester.tap(find.text('Probar con una URL'));
    await tester.pumpAndSettle();

    expect(find.text('Analizar URL'), findsOneWidget);
  });
}
