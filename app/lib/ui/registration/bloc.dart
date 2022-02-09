import 'dart:async';

import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:opaque_app/opaque.dart';

abstract class _RegisterEvent {}

class CheckUsername implements _RegisterEvent {
  final String username;

  CheckUsername(this.username);
}

class Register implements _RegisterEvent {
  final String password;

  Register(this.password);
}

class Reset implements _RegisterEvent {}

enum RegistrationStage {
  initial,
  checking,
  available,
  unavailable,
  registering,
  done,
}

class RegistrationState {
  final RegistrationStage stage;
  final String? username;
  final String? password;

  RegistrationState.initial({required this.username})
      : stage = RegistrationStage.initial,
        password = null;

  RegistrationState._({
    required this.stage,
    required this.username,
    required this.password,
  });

  RegistrationState checkUsername({required String username}) {
    return RegistrationState._(
      stage: RegistrationStage.checking,
      username: username,
      password: password,
    );
  }

  RegistrationState checkResult(bool isAvailable) {
    if (stage != RegistrationStage.checking &&
        stage != RegistrationStage.registering) {
      throw StateError('Not checking right now');
    }
    return RegistrationState._(
      stage: isAvailable
          ? RegistrationStage.available
          : RegistrationStage.unavailable,
      username: username,
      password: password,
    );
  }

  RegistrationState registering({required String password}) {
    if (stage != RegistrationStage.available) {
      throw StateError('Must be in stage available');
    }
    return RegistrationState._(
      stage: RegistrationStage.registering,
      username: username,
      password: password,
    );
  }

  RegistrationState done() {
    if (stage != RegistrationStage.registering) {
      throw StateError('Cannot be done in stage $stage');
    }
    return RegistrationState._(
      stage: RegistrationStage.done,
      username: username,
      password: password,
    );
  }

  RegistrationState reset() {
    return RegistrationState._(
      stage: RegistrationStage.initial,
      username: username,
      password: null,
    );
  }
}

class RegistrationBloc extends Bloc<_RegisterEvent, RegistrationState> {
  final OpaqueHandler _opaque;

  RegistrationBloc(
    this._opaque, {
    required String? initialUsername,
  }) : super(RegistrationState.initial(username: initialUsername)) {
    on<CheckUsername>(_checkUsername);
    on<Register>(_register);
    on<Reset>(_reset);
  }

  Future<bool> _checkAvailability(String username) async {
    // TODO implement?
    return true;
  }

  FutureOr<void> _checkUsername(
    CheckUsername event,
    Emitter<RegistrationState> emit,
  ) async {
    final username = event.username.trim();
    emit(state.checkUsername(username: username));
    final isAvailable = await _checkAvailability(username);
    emit(state.checkResult(isAvailable));
  }

  Future<bool> _registerUser({
    required String user,
    required String password,
  }) async {
    return await _opaque.register(username: user, password: password);
  }

  FutureOr<void> _register(
    Register event,
    Emitter<RegistrationState> emit,
  ) async {
    final password = event.password.trim();
    emit(state.registering(password: password));
    final result = await _registerUser(
      user: state.username!,
      password: password,
    );
    if (result) {
      emit(state.done());
    } else {
      emit(state.checkResult(false));
    }
  }

  FutureOr<void> _reset(
    Reset event,
    Emitter<RegistrationState> emit,
  ) {
    emit(state.reset());
  }
}
