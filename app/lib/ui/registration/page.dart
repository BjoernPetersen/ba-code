import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:opaque_app/opaque.dart';
import 'package:opaque_app/ui/registration/bloc.dart';
import 'package:provider/provider.dart';

class RegistrationPage extends StatelessWidget {
  final String? initialUsername;

  const RegistrationPage({
    Key? key,
    this.initialUsername,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Registration'),
      ),
      body: BlocProvider(
        create: (context) => RegistrationBloc(
          Provider.of<OpaqueHandler>(context, listen: false),
          initialUsername: initialUsername,
        ),
        child: const Padding(
          padding: EdgeInsets.symmetric(horizontal: 10),
          child: Center(child: _RegistrationProcess()),
        ),
      ),
    );
  }
}

class _RegistrationProcess extends StatelessWidget {
  const _RegistrationProcess();

  @override
  Widget build(BuildContext context) {
    return BlocConsumer<RegistrationBloc, RegistrationState>(
      listener: (context, state) {
        if (state.stage == RegistrationStage.unavailable) {
          final scaffold = ScaffoldMessenger.of(context);
          scaffold.showSnackBar(SnackBar(
            content: const Text('That username is not available'),
            action: SnackBarAction(
              label: 'Dismiss',
              onPressed: () => scaffold.hideCurrentSnackBar(),
            ),
            duration: const Duration(seconds: 5),
          ));
        }

        if (state.stage == RegistrationStage.done) {
          Navigator.of(context).pop();
          final scaffold = ScaffoldMessenger.of(context);
          scaffold.showSnackBar(SnackBar(
            content: const Text('Successfully registered'),
            action: SnackBarAction(
              label: 'Dismiss',
              onPressed: () => scaffold.hideCurrentSnackBar(),
            ),
            duration: const Duration(seconds: 2),
          ));
        }
      },
      builder: (context, state) {
        switch (state.stage) {
          case RegistrationStage.initial:
          case RegistrationStage.unavailable:
            return _UsernameForm(initialUsername: state.username);
          case RegistrationStage.registering:
          case RegistrationStage.checking:
          case RegistrationStage.done:
            return const CircularProgressIndicator();
          case RegistrationStage.available:
            return _PasswordForm(username: state.username!);
        }
      },
    );
  }
}

class _UsernameForm extends StatefulWidget {
  final String? initialUsername;

  const _UsernameForm({
    Key? key,
    required this.initialUsername,
  }) : super(key: key);

  @override
  State<_UsernameForm> createState() => _UsernameFormState();
}

class _UsernameFormState extends State<_UsernameForm> {
  late final TextEditingController _usernameController;

  @override
  void initState() {
    super.initState();
    _usernameController = TextEditingController(text: widget.initialUsername);
  }

  void _check() {
    BlocProvider.of<RegistrationBloc>(context)
        .add(CheckUsername(_usernameController.text));
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        TextField(
          controller: _usernameController,
          decoration: const InputDecoration(
            label: Text('Choose a username'),
          ),
        ),
        ValueListenableBuilder<TextEditingValue>(
          valueListenable: _usernameController,
          builder: (context, value, child) => ElevatedButton(
            onPressed: value.text.trim().isEmpty ? null : _check,
            child: child,
          ),
          child: const Text('Continue'),
        ),
      ],
    );
  }
}

class _PasswordForm extends StatefulWidget {
  final String username;

  const _PasswordForm({
    Key? key,
    required this.username,
  }) : super(key: key);

  @override
  State<_PasswordForm> createState() => _PasswordFormState();
}

class _PasswordFormState extends State<_PasswordForm> {
  late final TextEditingController _controller;

  @override
  void initState() {
    super.initState();
    _controller = TextEditingController();
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _register() {
    BlocProvider.of<RegistrationBloc>(context).add(Register(_controller.text));
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        Text(
          widget.username,
          style: Theme.of(context).textTheme.headline4,
        ),
        TextField(
          controller: _controller,
          keyboardType: TextInputType.visiblePassword,
          obscureText: true,
          decoration: const InputDecoration(
            label: Text('Choose a password'),
          ),
        ),
        ValueListenableBuilder<TextEditingValue>(
          valueListenable: _controller,
          builder: (context, value, child) => ElevatedButton(
            onPressed: value.text.trim().isEmpty ? null : _register,
            child: child,
          ),
          child: const Text('Register'),
        ),
      ],
    );
  }
}
