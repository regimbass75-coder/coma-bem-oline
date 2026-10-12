<?php
// API de eventos em homologação: armazenamento por restaurante, autorização e idempotência.
require_once __DIR__.'/lib.php';
require_once __DIR__.'/ug_permissions.php';
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, private');
header('X-Content-Type-Options: nosniff');
function sync_reply(int $status,array $data): void {http_response_code($status);echo json_encode($data,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);exit;}
$method=$_SERVER['REQUEST_METHOD']??'';
if(!in_array($method,['GET','POST'],true))sync_reply(405,['ok'=>false,'erro'=>'Método inválido']);
start_app();
$rid=(string)($_SESSION['restaurant_id']??'');$uid=(string)($_SESSION['user_id']??'');
if($rid===''||$uid==='')sync_reply(401,['ok'=>false,'erro'=>'Sessão necessária']);
$user=null;
foreach(read_json(USERS_FILE,[]) as $u)if(is_array($u)&&(string)($u['id']??'')===$uid&&(string)($u['restaurant_id']??'')===$rid&&($u['active']??true)===true){$user=$u;break;}
if(!$user||!ug_restaurant_active($rid))sync_reply(403,['ok'=>false,'erro'=>'Acesso negado']);
$lic=license_for_restaurant($rid);
if(!$lic||status_license($lic)!=='ATIVA')sync_reply(403,['ok'=>false,'erro'=>'Licença inválida']);
$permissions=ug_effective_permissions($user);
$allowed=['venda'=>'PDV/Vendas','caixa'=>'Caixa','produto'=>'Produtos','cliente'=>'Clientes','financeiro'=>'Financeiro'];
if($method==='POST'){
 $expected=$_SESSION['ug_csrf']??'';$provided=$_SERVER['HTTP_X_UG_CSRF']??'';
 if(!is_string($expected)||strlen($expected)!==64||!is_string($provided)||!hash_equals($expected,$provided))sync_reply(403,['ok'=>false,'erro'=>'CSRF inválido']);
 $raw=file_get_contents('php://input',false,null,0,65537);
 if($raw===false||strlen($raw)>65536)sync_reply(413,['ok'=>false,'erro'=>'Evento excede 64 KB']);
 $e=json_decode($raw,true);
 if(!is_array($e)||array_is_list($e))sync_reply(400,['ok'=>false,'erro'=>'JSON inválido']);
 $type=$e['type']??'';$eventId=$e['event_id']??'';
 if(!is_string($type)||!isset($allowed[$type])||!in_array($allowed[$type],$permissions,true))sync_reply(403,['ok'=>false,'erro'=>'Módulo não autorizado']);
 if(!is_string($eventId)||!preg_match('/^[A-Za-z0-9_-]{12,100}$/D',$eventId))sync_reply(400,['ok'=>false,'erro'=>'ID de evento inválido']);
 if(!isset($e['payload'])||!is_array($e['payload'])||array_is_list($e['payload']))sync_reply(400,['ok'=>false,'erro'=>'Payload inválido']);
 if(isset($e['restaurant_id'])&&(string)$e['restaurant_id']!==$rid)sync_reply(403,['ok'=>false,'erro'=>'Restaurante divergente']);
}
// Arquivos sob pasta privada; proteção HTTP da hospedagem precisa ser comprovada.
$dir=DATA_DIR.'/sync';if(!is_dir($dir)&&!mkdir($dir,0750,true)&&!is_dir($dir))sync_reply(500,['ok'=>false,'erro'=>'Armazenamento indisponível']);
$deny=$dir.'/.htaccess';if(!is_file($deny))file_put_contents($deny,"Require all denied\n",LOCK_EX);
$path=$dir.'/'.hash('sha256',$rid).'.jsonl';$fp=@fopen($path,'c+b');if(!$fp)sync_reply(500,['ok'=>false,'erro'=>'Armazenamento indisponível']);
try{
 if(!flock($fp,$method==='POST'?LOCK_EX:LOCK_SH))sync_reply(500,['ok'=>false,'erro'=>'Bloqueio indisponível']);
 rewind($fp);$rows=[];$seen=[];
 while(($line=fgets($fp))!==false){$item=json_decode($line,true);if(!is_array($item)||!isset($item['seq'],$item['event_id'],$item['type'],$item['fingerprint'])||!is_int($item['seq'])||$item['seq']<1||!is_string($item['event_id'])||!is_string($item['type']))sync_reply(500,['ok'=>false,'erro'=>'Registro corrompido']);if(isset($seen[$item['event_id']]))sync_reply(500,['ok'=>false,'erro'=>'IDs duplicados no registro']);$rows[]=$item;$seen[$item['event_id']]=$item;}
 if($method==='GET'){
  $rawCursor=$_GET['after']??'0';
  if(!is_string($rawCursor)||!preg_match('/^(0|[1-9][0-9]{0,17})$/D',$rawCursor))sync_reply(400,['ok'=>false,'erro'=>'Cursor inválido']);
  $cursor=(int)$rawCursor;
  if($cursor<0)sync_reply(400,['ok'=>false,'erro'=>'Cursor inválido']);
  $result=[];foreach($rows as $item)if($item['seq']>$cursor&&in_array($allowed[$item['type']]??'', $permissions,true)){$result[]=$item;if(count($result)>=100)break;}
  sync_reply(200,['ok'=>true,'events'=>$result,'next_cursor'=>$result?end($result)['seq']:$cursor]);
 }
 $fingerprint=hash('sha256',json_encode([$type,$e['payload']],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR));
 if(isset($seen[$eventId])){
  if(!hash_equals($seen[$eventId]['fingerprint']??'',$fingerprint))sync_reply(409,['ok'=>false,'erro'=>'ID já utilizado com outro conteúdo']);
  sync_reply(200,['ok'=>true,'duplicate'=>true,'seq'=>$seen[$eventId]['seq']]);
 }
 $seq=$rows?end($rows)['seq']+1:1;
 $entry=['seq'=>$seq,'event_id'=>$eventId,'type'=>$type,'payload'=>$e['payload'],'user_id'=>$uid,'restaurant_id'=>$rid,'fingerprint'=>$fingerprint,'created_at'=>gmdate('c')];
 $encoded=json_encode($entry,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."\n";
 fseek($fp,0,SEEK_END);$offset=ftell($fp);$written=fwrite($fp,$encoded);
 if($written!==strlen($encoded)||!fflush($fp)){ftruncate($fp,$offset);sync_reply(500,['ok'=>false,'erro'=>'Falha ao persistir']);}
 sync_reply(201,['ok'=>true,'duplicate'=>false,'seq'=>$seq]);
}finally{flock($fp,LOCK_UN);fclose($fp);}
