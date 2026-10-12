<?php
require_once __DIR__.'/lib.php';
// Registro de sessões com trava única por restaurante; nenhum token de sessão é persistido em claro.
function ug_session_registry(string $rid, callable $callback) {
  if (!preg_match('/^[A-Za-z0-9_-]{1,80}$/D',$rid)) throw new RuntimeException('ID inválido');
  $dir=DATA_DIR.'/sessions';
  if (!is_dir($dir) && !mkdir($dir,0750,true) && !is_dir($dir)) throw new RuntimeException('Sessões indisponíveis');
  if (!file_exists($dir.'/.htaccess')) @file_put_contents($dir.'/.htaccess',"Require all denied\n",LOCK_EX);
  $file=$dir.'/'.hash('sha256',$rid).'.json';
  $fp=fopen($file,'c+'); if(!$fp) throw new RuntimeException('Registro indisponível');
  try {
    if(!flock($fp,LOCK_EX))throw new RuntimeException('Trava indisponível');
    rewind($fp);$raw=stream_get_contents($fp);$rows=json_decode($raw?:'[]',true);
    if(!is_array($rows))throw new RuntimeException('Registro corrompido');
    $now=time();$rows=array_values(array_filter($rows,fn($r)=>is_array($r)&&($r['expires']??0)>$now));
    $result=$callback($rows,$now);
    $json=json_encode($rows,JSON_THROW_ON_ERROR);
    rewind($fp);if(!ftruncate($fp,0)||fwrite($fp,$json)!==strlen($json)||!fflush($fp))throw new RuntimeException('Falha no registro');
    return $result;
  }finally{flock($fp,LOCK_UN);fclose($fp);}
}
function ug_session_claim(string $rid,string $uid,int $limit):bool {
  $limit=max(1,min(500,$limit));$hash=hash('sha256',session_id());
  return ug_session_registry($rid,function(&$rows,$now)use($uid,$limit,$hash){
    $rows=array_values(array_filter($rows,fn($r)=>($r['token']??'')!==$hash));
    if(count($rows)>=$limit)return false;
    $rows[]=['token'=>$hash,'uid'=>$uid,'expires'=>$now+1800];return true;
  });
}
function ug_session_valid():bool {
  $rid=(string)($_SESSION['restaurant_id']??'');$uid=(string)($_SESSION['user_id']??'');
  if($rid===''||$uid==='')return false;
  $hash=hash('sha256',session_id());
  return ug_session_registry($rid,function(&$rows,$now)use($hash,$uid){
    foreach($rows as &$row){if(hash_equals((string)($row['token']??''),$hash)&&($row['uid']??'')===$uid){$row['expires']=$now+1800;return true;}}
    return false;
  });
}
function ug_session_release():void {
  $rid=(string)($_SESSION['restaurant_id']??'');if($rid==='')return;
  $hash=hash('sha256',session_id());
  ug_session_registry($rid,function(&$rows,$now)use($hash){$rows=array_values(array_filter($rows,fn($r)=>($r['token']??'')!==$hash));});
}
