import 'package:flutter/material.dart';

import 'api_service.dart';

void main() {
  runApp(const PharmacyApp());
}

class PharmacyApp extends StatelessWidget {
  const PharmacyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Healthcare Pharmacy',
      theme: ThemeData(colorSchemeSeed: Colors.blue, useMaterial3: true),
      home: const LoginPage(),
    );
  }
}

class LoginPage extends StatefulWidget {
  const LoginPage({super.key});

  @override
  State<LoginPage> createState() => _LoginPageState();
}

class _LoginPageState extends State<LoginPage> {
  final _email = TextEditingController(text: 'admin@pharmacy.com');
  final _password = TextEditingController(text: 'admin123');
  final _api = ApiService();
  String _error = '';

  Future<void> _login() async {
    final res = await _api.login(_email.text.trim(), _password.text);
    if (res['ok'] == true && res['token'] != null) {
      await _api.saveToken(res['token'] as String);
      if (!mounted) return;
      Navigator.pushReplacement(context, MaterialPageRoute(builder: (_) => const MedicinesPage()));
      return;
    }
    setState(() => _error = (res['error'] ?? 'Login failed').toString());
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Login')),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            TextField(controller: _email, decoration: const InputDecoration(labelText: 'Email')),
            const SizedBox(height: 12),
            TextField(controller: _password, decoration: const InputDecoration(labelText: 'Password'), obscureText: true),
            const SizedBox(height: 12),
            if (_error.isNotEmpty) Text(_error, style: const TextStyle(color: Colors.red)),
            const SizedBox(height: 12),
            ElevatedButton(onPressed: _login, child: const Text('Login')),
          ],
        ),
      ),
    );
  }
}

class MedicinesPage extends StatefulWidget {
  const MedicinesPage({super.key});

  @override
  State<MedicinesPage> createState() => _MedicinesPageState();
}

class _MedicinesPageState extends State<MedicinesPage> {
  final _api = ApiService();
  List<dynamic> _items = [];
  String _msg = '';

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final items = await _api.medicines();
    setState(() => _items = items);
  }

  Future<void> _add(int id) async {
    final res = await _api.addToCart(id);
    setState(() => _msg = (res['ok'] == true) ? 'Added to cart' : (res['error'] ?? 'Failed').toString());
  }

  Future<void> _checkout() async {
    final res = await _api.checkout();
    setState(() => _msg = (res['ok'] == true) ? 'Order #${res['order_id']} placed' : (res['error'] ?? 'Checkout failed').toString());
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Medicines'),
        actions: [IconButton(onPressed: _checkout, icon: const Icon(Icons.shopping_cart_checkout))],
      ),
      body: Column(
        children: [
          if (_msg.isNotEmpty) Padding(padding: const EdgeInsets.all(8), child: Text(_msg)),
          Expanded(
            child: ListView.builder(
              itemCount: _items.length,
              itemBuilder: (_, i) {
                final m = _items[i] as Map<String, dynamic>;
                return ListTile(
                  title: Text((m['name'] ?? '').toString()),
                  subtitle: Text('INR ${(m['price'] ?? '').toString()}'),
                  trailing: IconButton(icon: const Icon(Icons.add_shopping_cart), onPressed: () => _add((m['id'] as num).toInt())),
                );
              },
            ),
          ),
        ],
      ),
    );
  }
}
