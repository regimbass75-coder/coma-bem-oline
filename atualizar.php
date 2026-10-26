<?php
declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
require_once __DIR__.'/licenca/lib.php';
start_admin();
if (empty($_SESSION['master_ok'])) {
 http_response_code(401);
 echo json_encode(['ok'=>false,'message'=>'Entre no Painel Master de testes.'],JSON_UNESCAPED_UNICODE); exit;
}
if (($_SERVER['REQUEST_METHOD']??'')!=='POST') {
 http_response_code(405);
 echo json_encode(['ok'=>false,'message'=>'Use o formulário da Atualização Central.'],JSON_UNESCAPED_UNICODE); exit;
}
$token=$_POST['ug_csrf']??'';
$saved=$_SESSION['ug_master_csrf']??'';
if (!is_string($token)||!is_string($saved)||!preg_match('/^[a-f0-9]{64}$/D',$saved)||!hash_equals($saved,$token)) {
 http_response_code(403);
 echo json_encode(['ok'=>false,'message'=>'Token de segurança inválido.'],JSON_UNESCAPED_UNICODE); exit;
}
http_response_code(409);
echo json_encode(['ok'=>false,'message'=>'Pacote de produção não instalado. No Render, o Painel Master (Docker/PHP) e o Gestor (Python/Flask) são serviços separados. A atualização deve ser aplicada à branch homologacao-dep1 e implantada no serviço correspondente, após validação. Nenhum arquivo foi alterado.'],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
