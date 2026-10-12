<?php
require_once __DIR__.'/lib.php';
require_once __DIR__.'/ug_permissions.php';
require_once __DIR__.'/csrf.php';
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
function ug_auth_reply($code,$ok,$msg){http_response_code($code);echo json_encode(['ok'=>$ok,'message'=>$msg]);exit;}
if($_SERVER['REQUEST_METHOD']!=='POST')ug_auth_reply(405,false,'Use POST.');
start_app();
$operator=ug_require_user_module('PDV/Vendas');
ug_require_csrf();
$body=json_decode(file_get_contents('php://input'),true);
if(!is_array($body))$body=$_POST;
$password=(string)($body['password']??'');
if($password===''||strlen($password)>1024)ug_auth_reply(400,false,'Senha obrigatória.');
$role=strtoupper((string)($operator['role']??''));
if(!in_array($role,['ADMINISTRADOR','GERENTE'],true))ug_auth_reply(403,false,'Somente administrador ou gerente.');
if(!password_verify($password,(string)($operator['password_hash']??'')))ug_auth_reply(403,false,'Autorização recusada.');
ug_auth_reply(200,true,'Operador autorizado.');
