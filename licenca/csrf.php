<?php
// CSRF: exige token por sessão em operações que modificam dados.
// Complementa, não substitui, a autorização do módulo.
require_once __DIR__ . '/lib.php';
function ug_require_csrf(): void {
    start_app();
    header('Cache-Control: no-store');
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        http_response_code(405);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok'=>false,'erro'=>'Método não permitido.']);
        exit;
    }
    $expected = $_SESSION['ug_csrf'] ?? '';
    // A comparação usa token aleatório vinculado à sessão autenticada.
    $provided = $_SERVER['HTTP_X_UG_CSRF'] ?? ($_POST['ug_csrf'] ?? '');
    if (!is_string($expected) || strlen($expected) !== 64 ||
        !is_string($provided) || !hash_equals($expected, $provided)) {
        http_response_code(403);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok'=>false,'erro'=>'Token de segurança ausente ou inválido.']);
        exit;
    }
}
