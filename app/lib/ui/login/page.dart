import 'package:flutter/material.dart';

class LoginPage extends StatelessWidget {
  const LoginPage({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('OPAQUE Demonstrator'),
      ),
      body: const Center(
        child: _LoginForm(),
      ),
    );
  }
}

class _LoginForm extends StatefulWidget {
  const _LoginForm({Key? key}) : super(key: key);

  @override
  State<_LoginForm> createState() => _LoginFormState();
}

class _LoginFormState extends State<_LoginForm> {
  late final TextEditingController _usernameController;
  late final TextEditingController _passwordController;

  @override
  void initState() {
    super.initState();
    _usernameController = TextEditingController();
    _passwordController = TextEditingController();
  }

  @override
  void dispose() {
    _usernameController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  Future<void> _submit() async {}

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        TextField(controller: _usernameController),
        TextField(
          controller: _passwordController,
          obscureText: true,
          keyboardType: TextInputType.visiblePassword,
        ),
        TextButton(
          onPressed: _submit,
          child: const Text('Submit'),
        ),
      ],
    );
  }
}
