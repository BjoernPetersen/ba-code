import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:opaque_app/opaque.dart';
import 'package:opaque_app/ui/loggedin/page.dart';
import 'package:opaque_app/ui/login/bloc.dart';
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
      body: BlocProvider(
        create: (context) => LoginBloc(Provider.of<OpaqueHandler>(
          context,
          listen: false,
        )),
        child: const _LoginProcess(),
      ),
    );
  }
}

class _LoginProcess extends StatelessWidget {
  const _LoginProcess();

  @override
  Widget build(BuildContext context) {
    return BlocConsumer<LoginBloc, LoginState>(
      builder: (context, state) {
        switch (state.stage) {
          case LoginStage.initial:
          case LoginStage.failed:
            return const _LoginForm();
          case LoginStage.success:
          case LoginStage.loading:
            return const Center(child: CircularProgressIndicator());
        }
      },
      listener: (context, state) {
        final scaffold = ScaffoldMessenger.of(context);
        if (state.stage == LoginStage.success) {
          scaffold.showSnackBar(SnackBar(
            content: const Text('Successfully logged in'),
            duration: const Duration(seconds: 1),
            action: SnackBarAction(
              label: 'Dismiss',
              onPressed: () => scaffold.hideCurrentSnackBar(),
            ),
          ));
          Navigator.of(context).pushReplacement(MaterialPageRoute(
            builder: (context) => const LoggedInPage(),
          ));
        }

        if (state.stage == LoginStage.failed) {
          scaffold.showSnackBar(SnackBar(
            content: const Text('Log in failed, try again!'),
            duration: const Duration(seconds: 2),
            action: SnackBarAction(
              label: 'Dismiss',
              onPressed: () => scaffold.hideCurrentSnackBar(),
            ),
          ));
        }
      },
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

  bool get _hasValues =>
      _usernameController.text.trim().isNotEmpty &&
      _passwordController.text.trim().isNotEmpty;

  @override
  void initState() {
    super.initState();
    _usernameController = TextEditingController();
    _usernameController.addListener(() => setState(() {}));
    _passwordController = TextEditingController();
    _passwordController.addListener(() => setState(() {}));
  }

  @override
  void dispose() {
    _usernameController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  void _login() {
    BlocProvider.of<LoginBloc>(context).add(Login(
      Credentials(
        username: _usernameController.text,
        password: _passwordController.text,
      ),
    ));
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
          onPressed: _hasValues ? _login : null,
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
