<?php
require_once __DIR__ . '/require_permission.php';
// Token emitido somente para uma sessão de usuário autorizada.
ug_require_module(['PDV/Vendas','Produtos','Configurações']);
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
if (!isset($_SESSION['ug_csrf']) || !is_string($_SESSION['ug_csrf']) || !preg_match('/^[a-f0-9]{64}$/D', $_SESSION['ug_csrf'])) $_SESSION['ug_csrf'] = bin2hex(random_bytes(32));
echo json_encode(['ok'=>true,'csrf'=>$_SESSION['ug_csrf']]);
