import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:opaque_app/opaque.dart';
import 'package:opaque_app/secure_client.dart';
import 'package:opaque_app/ui/login/page.dart';
import 'package:provider/provider.dart';

class LoggedInPage extends StatelessWidget {
  const LoggedInPage({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    final opaque = Provider.of<OpaqueHandler>(context);
    return Scaffold(
      appBar: AppBar(
        title: Text('Logged in as ${opaque.username}'),
        actions: const [
          _LogoutAction(),
        ],
      ),
      body: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 10),
        child: Center(
          child: LoggedInContent(client: opaque.secureClient),
        ),
      ),
    );
  }
}

class LoggedInContent extends StatefulWidget {
  final SecureClient client;

  const LoggedInContent({
    Key? key,
    required this.client,
  }) : super(key: key);

  @override
  State<LoggedInContent> createState() => _LoggedInContentState();
}

class _LoggedInContentState extends State<LoggedInContent> {
  late Future<String> _loadContent;

  Future<String> _loadTextPage(String path) async {
    final bytes = await widget.client.get(path: path);
    const decoder = Utf8Decoder();
    return decoder.convert(bytes);
  }

  @override
  void initState() {
    super.initState();
    _loadContent = _loadTextPage('/');
  }

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<String>(
      future: _loadContent,
      builder: (context, state) {
        if (state.hasData) {
          return Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Text(
                'Response from the server:',
                textScaleFactor: 1.2,
              ),
              const SizedBox(height: 20),
              Text(
                state.data!,
                textAlign: TextAlign.center,
              )
            ],
          );
        }
        if (state.hasError) {
          return Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Text('An error occurred!'),
              ElevatedButton.icon(
                onPressed: () => setState(() {
                  _loadContent = _loadTextPage('/');
                }),
                icon: const Icon(Icons.refresh),
                label: const Text('Retry'),
              ),
            ],
          );
        }
        return const CircularProgressIndicator();
      },
    );
  }
}

class _LogoutAction extends StatelessWidget {
  const _LogoutAction();

  void _logout(BuildContext context) {
    Provider.of<OpaqueHandler>(
      context,
      listen: false,
    ).logout();
    Navigator.of(context).pushReplacement(MaterialPageRoute(
      builder: (context) => const LoginPage(),
    ));
  }

  @override
  Widget build(BuildContext context) {
    return IconButton(
      onPressed: () => _logout(context),
      icon: const Icon(Icons.logout),
      tooltip: 'Logout',
    );
  }
}
