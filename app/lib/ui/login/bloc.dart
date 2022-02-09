import 'dart:async';

import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:opaque_app/opaque.dart';

abstract class _LoginEvent {}

class Credentials {
  final String username;
  final String password;

  Credentials({
    required String username,
    required String password,
  })  : username = username.trim(),
        password = password.trim();
}

class Login implements _LoginEvent {
  final Credentials credentials;

  Login(this.credentials);
}

enum LoginStage {
  initial,
  loading,
  failed,
  success,
}

class LoginState {
  final LoginStage stage;
  final Credentials? credentials;

  LoginState.initial()
      : stage = LoginStage.initial,
        credentials = null;

  LoginState._({
    required this.stage,
    required this.credentials,
  });

  LoginState login(Credentials credentials) {
    return LoginState._(stage: LoginStage.loading, credentials: credentials);
  }

  LoginState loginResult(bool success) {
    return LoginState._(
      stage: success ? LoginStage.success : LoginStage.failed,
      credentials: credentials,
    );
  }
}

class LoginBloc extends Bloc<_LoginEvent, LoginState> {
  final OpaqueHandler _opaque;

  LoginBloc(this._opaque) : super(LoginState.initial()) {
    on<Login>(_login);
  }

  FutureOr<void> _login(Login event, Emitter<LoginState> emit) async {
    final credentials = event.credentials;
    emit(state.login(credentials));
    final success = await _opaque.login(
      username: credentials.username,
      password: credentials.password,
    );
    emit(state.loginResult(success));
  }
}
