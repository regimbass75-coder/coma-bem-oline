<?php
declare(strict_types=1);
require_once __DIR__.'/lib.php';
start_admin();
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
if(empty($_SESSION['master_ok'])){http_response_code(401);echo json_encode(['ok'=>false,'message'=>'Não autenticado']);exit;}
if(!isset($_SESSION['ug_master_csrf'])||!is_string($_SESSION['ug_master_csrf'])||!preg_match('/^[a-f0-9]{64}$/D',$_SESSION['ug_master_csrf']))
 $_SESSION['ug_master_csrf']=bin2hex(random_bytes(32));
echo json_encode(['ok'=>true,'csrf'=>$_SESSION['ug_master_csrf']]);
