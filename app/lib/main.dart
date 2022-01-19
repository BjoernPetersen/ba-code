import 'package:flutter/material.dart';
import 'package:opaque_app/opaque.dart';
import 'package:opaque_app/ui/login/page.dart';
import 'package:provider/provider.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({Key? key}) : super(key: key);

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return Provider<OpaqueHandler>(
      create: (context) => OpaqueHandler(),
      child: MaterialApp(
        title: 'Opaque Demonstrator',
        theme: ThemeData(
          primarySwatch: Colors.blue,
        ),
        home: const LoginPage(),
      ),
    );
  }
}
