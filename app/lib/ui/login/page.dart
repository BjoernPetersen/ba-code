import 'package:flutter/material.dart';
import 'package:opaque_app/opaque.dart';
import 'package:opaque_app/ui/registration/page.dart';
import 'package:provider/provider.dart';

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

  void _login() {
    Provider.of<OpaqueHandler>(context).login(
      username: _usernameController.text,
      password: _passwordController.text,
    );
  }

  void _register() {
    Navigator.of(context).push(MaterialPageRoute(
      builder: (context) => RegistrationPage(
        initialUsername: _usernameController.text,
      ),
    ));
  }

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
        ElevatedButton(
          onPressed: _login,
          child: const Text('Log in'),
        ),
        TextButton(
          onPressed: _register,
          child: const Text('Not registered yet?'),
        ),
      ],
    );
  }
}
