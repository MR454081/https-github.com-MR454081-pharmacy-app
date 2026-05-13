import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

import 'config.dart';

class ApiService {
  Future<String?> token() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString('token');
  }

  Future<void> saveToken(String token) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('token', token);
  }

  Future<void> clearToken() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('token');
  }

  Future<Map<String, String>> _headers({bool auth = false}) async {
    final headers = {'Content-Type': 'application/json'};
    if (auth) {
      final t = await token();
      if (t != null && t.isNotEmpty) {
        headers['Authorization'] = 'Bearer $t';
      }
    }
    return headers;
  }

  Future<Map<String, dynamic>> login(String email, String password) async {
    final res = await http.post(
      Uri.parse('${ApiConfig.baseUrl}/api/auth/login'),
      headers: await _headers(),
      body: jsonEncode({'email': email, 'password': password}),
    );
    return jsonDecode(res.body) as Map<String, dynamic>;
  }

  Future<List<dynamic>> medicines() async {
    final res = await http.get(Uri.parse('${ApiConfig.baseUrl}/api/medicines'));
    final body = jsonDecode(res.body) as Map<String, dynamic>;
    return (body['items'] ?? []) as List<dynamic>;
  }

  Future<Map<String, dynamic>> cart() async {
    final res = await http.get(
      Uri.parse('${ApiConfig.baseUrl}/api/cart'),
      headers: await _headers(auth: true),
    );
    return jsonDecode(res.body) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> addToCart(int medicineId) async {
    final res = await http.post(
      Uri.parse('${ApiConfig.baseUrl}/api/cart/add'),
      headers: await _headers(auth: true),
      body: jsonEncode({'medicine_id': medicineId, 'quantity': 1}),
    );
    return jsonDecode(res.body) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> checkout() async {
    final res = await http.post(
      Uri.parse('${ApiConfig.baseUrl}/api/checkout'),
      headers: await _headers(auth: true),
      body: jsonEncode({'shipping_address': 'Mobile App Address', 'payment_provider': 'cod'}),
    );
    return jsonDecode(res.body) as Map<String, dynamic>;
  }
}
