import 'package:flutter/material.dart';

import 'presentation/utrust_colors.dart';
import 'screens/home_screen.dart';

//Arranque, funcion principal
void main() {
  runApp(const UTrustApp());
}

//Widget raíz de la app
class UTrustApp extends StatefulWidget {
  const UTrustApp({
    super.key,
  }); //super.key, identifica el widget dentro del árbol de widget

  @override
  State<UTrustApp> createState() => _UTrustAppState();
}

class _UTrustAppState extends State<UTrustApp> {
  bool _useDarkTheme = true;

  void _setThemeStyle(bool useDarkTheme) {
    setState(() => _useDarkTheme = useDarkTheme);
  }

  //Método obligatorio para la interfaz del widget
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'UTrust',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: UTrustColors.themeSeedLight,
          brightness: Brightness.light,
        ),
      ),
      darkTheme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: UTrustColors.themeSeedDark,
          brightness: Brightness.dark,
        ),
        scaffoldBackgroundColor: UTrustColors.darkScaffold,
        cardTheme: const CardThemeData(
          color: UTrustColors.darkCard,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.all(Radius.circular(8)),
          ),
        ),
      ),
      themeMode: _useDarkTheme ? ThemeMode.dark : ThemeMode.light,
      home: HomeScreen(
        useDarkTheme: _useDarkTheme,
        onThemeChanged: _setThemeStyle,
      ),
    );
  }
}
