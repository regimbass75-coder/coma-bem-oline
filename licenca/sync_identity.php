<?php
// Identidade de restaurante verificada exclusivamente na sessão do servidor.
require_once __DIR__.'/lib.php';
require_once __DIR__.'/ug_permissions.php';
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, private');
header('X-Content-Type-Options: nosniff');
function identity_reply($status,$body){http_response_code($status);echo json_encode($body,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);exit;}
if($_SERVER['REQUEST_METHOD']!=='GET')identity_reply(405,['ok'=>false,'erro'=>'Método não permitido']);
start_app();
$uid=(string)($_SESSION['user_id']??'');
$rid=(string)($_SESSION['restaurant_id']??'');
if($uid===''||$rid==='')identity_reply(401,['ok'=>false,'erro'=>'Sessão necessária']);
$matched=null;
foreach(read_json(USERS_FILE,[]) as $u){
 if(is_array($u)&&(string)($u['id']??'')===$uid&&(string)($u['restaurant_id']??'')===$rid&&($u['active']??true)===true){$matched=$u;break;}
}
if(!$matched||!ug_restaurant_active($rid))identity_reply(403,['ok'=>false,'erro'=>'Usuário ou restaurante inativo']);
$license=license_for_restaurant($rid);
if(!$license||status_license($license)!=='ATIVA')identity_reply(403,['ok'=>false,'erro'=>'Licença inválida']);
identity_reply(200,['ok'=>true,'restaurant_id'=>$rid,'user_id'=>$uid,'permissions'=>ug_effective_permissions($matched)]);
