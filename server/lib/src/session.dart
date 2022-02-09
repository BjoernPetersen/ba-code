import 'package:opaque/server.dart' as opaque;

class SessionManager {
  final Map<String, SessionSecurity> _sessions = {};

  void setSession(String username, SessionSecurity session) {
    _sessions[username] = session;
  }

  SessionSecurity? getSession(String username) {
    return _sessions[username];
  }
}

typedef SessionSecurity = opaque.SessionSecurity;
