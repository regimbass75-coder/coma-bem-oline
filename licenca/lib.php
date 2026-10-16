<?php
// Configurável para volume persistente externo; padrão antigo mantido apenas para homologação.
// No Render Free, o diretório local continua temporário mesmo com esta opção.
define('DATA_DIR', (static function(){
 $configured = trim((string)(getenv('UG_DATA_DIR') ?: ''));
 if($configured === '') return __DIR__ . '/data';
 if($configured[0] !== '/') throw new RuntimeException('UG_DATA_DIR deve ser um caminho absoluto');
 return rtrim($configured, '/');
})());
const ADMIN_FILE = DATA_DIR . '/admin.json';
const LICENSE_FILE = DATA_DIR . '/licenses.json';
const RESTAURANTS_FILE = DATA_DIR . '/restaurants.json';
const USERS_FILE = DATA_DIR . '/users.json';
const FINANCE_FILE = DATA_DIR . '/finance.json';
function ensure_data(){
 if(!is_dir(DATA_DIR) && !mkdir(DATA_DIR,0750,true) && !is_dir(DATA_DIR))throw new RuntimeException('Pasta de dados indisponível');
 // Apache: impede download direto de JSONs, incluindo os de backup; Nginx requer regra no servidor.
 $deny=DATA_DIR.'/.htaccess';
 if(!file_exists($deny)) @file_put_contents($deny,"Require all denied\n",LOCK_EX);
 $legacy=dirname(__DIR__).'/comabem/licenca/data';
 if(is_dir($legacy) && !file_exists($legacy.'/.htaccess')) @file_put_contents($legacy.'/.htaccess',"Require all denied\n",LOCK_EX);
 foreach([LICENSE_FILE=>'[]',RESTAURANTS_FILE=>'[]',USERS_FILE=>'[]'] as $f=>$v)
  if(!file_exists($f) && @file_put_contents($f,$v,LOCK_EX)===false)throw new RuntimeException('Não foi possível inicializar dados');
}
function read_json($f,$default=[]){
 ensure_data();
 if(!is_file($f))return $default;
 $x=@file_get_contents($f);
 if($x===false)throw new RuntimeException('Não foi possível ler arquivo de dados: '.basename($f));
 $d=json_decode($x,true);
 if(json_last_error()!==JSON_ERROR_NONE||!is_array($d))throw new RuntimeException('Arquivo de dados inválido; operação interrompida: '.basename($f));
 return $d;
}
function write_json($f,$d){
 ensure_data();
 $json=json_encode($d,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
 $tmp=$f.'.'.bin2hex(random_bytes(8)).'.tmp';
 $fp=@fopen($tmp,'xb');
 if(!$fp)throw new RuntimeException('Não foi possível criar arquivo temporário');
 try{
  if(!flock($fp,LOCK_EX)||fwrite($fp,$json)!==strlen($json)||!fflush($fp))throw new RuntimeException('Falha ao gravar JSON');
 }finally{fclose($fp);}
 @chmod($tmp,0640);
 if(!@rename($tmp,$f)){@unlink($tmp);throw new RuntimeException('Falha ao confirmar JSON');}
}
function configured(){ return file_exists(ADMIN_FILE) && !empty(read_json(ADMIN_FILE)['password_hash']); }
function start_admin(){ if(session_status()!==PHP_SESSION_ACTIVE){ ini_set('session.use_strict_mode','1'); ini_set('session.cookie_httponly','1'); ini_set('session.cookie_samesite','Lax'); if(!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS']!=='off')ini_set('session.cookie_secure','1'); session_name('COMABEM_MASTER'); session_start(); } }
function require_admin(){ start_admin(); if(empty($_SESSION['master_ok'])){ header('Location: setup.php'); exit; } }
function start_app(){ if(session_status()!==PHP_SESSION_ACTIVE){ ensure_data(); $sessionDir=DATA_DIR.'/app-php-sessions'; if(!is_dir($sessionDir) && !mkdir($sessionDir,0700,true) && !is_dir($sessionDir))throw new RuntimeException('Diretório de sessões indisponível'); session_save_path($sessionDir); ini_set('session.use_strict_mode','1'); ini_set('session.cookie_httponly','1'); ini_set('session.cookie_samesite','Lax'); if(!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS']!=='off')ini_set('session.cookie_secure','1'); session_name('COMABEM_APP'); session_start(); } }
function keygen(){ $raw=strtoupper(bin2hex(random_bytes(8))); return 'CB-'.substr($raw,0,4).'-'.substr($raw,4,4).'-'.substr($raw,8,4).'-'.substr($raw,12,4); }
function restaurant_id(){ return 'REST-'.strtoupper(substr(bin2hex(random_bytes(5)),0,10)); }
function temp_password(){ return 'CB'.random_int(100000,999999); }
function status_license($l){ if(!empty($l['blocked'])) return 'BLOQUEADA'; if(empty($l['expires_at'])) return 'VENCIDA'; return strtotime($l['expires_at'].' 23:59:59')>=time()?'ATIVA':'VENCIDA'; }
function days_left($l){ if(status_license($l)!=='ATIVA') return 0; return max(0,(int)ceil((strtotime($l['expires_at'].' 23:59:59')-time())/86400)); }
function h($s){ return htmlspecialchars((string)$s,ENT_QUOTES,'UTF-8'); }
function find_user($login){ $login=strtolower(trim((string)$login)); foreach(read_json(USERS_FILE,[]) as $u){ if(($u['active']??true)!==true) continue; if(strtolower(trim((string)($u['login']??'')))===$login) return $u; } return null; }
function license_for_restaurant($rid){ foreach(read_json(LICENSE_FILE,[]) as $l) if((string)($l['restaurant_id']??'')===(string)$rid) return $l; return null; }

// Serializa operações administrativas entre processos e revalida dados sob o bloqueio.
function ug_master_locked(callable $callback){
 ensure_data();
 $fp=@fopen(DATA_DIR.'/.master.lock','c');
 if(!$fp)throw new RuntimeException('Bloqueio administrativo indisponível');
 try{
  if(!flock($fp,LOCK_EX))throw new RuntimeException('Falha no bloqueio administrativo');
  return $callback();
 }finally{flock($fp,LOCK_UN);fclose($fp);}
}
// Criação coordenada: em falha de gravação, tenta repor todos os arquivos originais.
// Não é transação de banco de dados; em queda brusca do processo ainda exige recuperação.
function ug_master_create_bundle(array $restaurant,array $license,array $user){
 return ug_master_locked(function()use($restaurant,$license,$user){
  $files=[RESTAURANTS_FILE,LICENSE_FILE,USERS_FILE];
  $rows=array_map(fn($f)=>read_json($f,[]),$files);
  $login=strtolower(trim((string)($user['login']??'')));
  if($login===''||trim((string)($restaurant['name']??''))==='')throw new InvalidArgumentException('Nome da empresa e login são obrigatórios');
  foreach($rows[2] as $u)if(strtolower(trim((string)($u['login']??'')))===$login)throw new DomainException('Login já cadastrado');
  foreach($rows[0] as $r)if(($r['id']??null)===$restaurant['id'])throw new DomainException('ID de empresa duplicado');
  foreach($rows[1] as $l)if(($l['key']??null)===$license['key'])throw new DomainException('Chave duplicada');
  $original=array_map(fn($f)=>file_get_contents($f),$files);
  $rows[0][]=$restaurant;$rows[1][]=$license;$rows[2][]=$user;
  $saved=[];
  try{foreach($files as $i=>$f){write_json($f,$rows[$i]);$saved[]=$i;}}
  catch(Throwable $e){
   $rollbackOk=true;
   foreach(array_reverse($saved) as $i){
    $temp=$files[$i].'.'.bin2hex(random_bytes(8)).'.rollback';
    if(file_put_contents($temp,$original[$i],LOCK_EX)===false||!rename($temp,$files[$i])){$rollbackOk=false;@unlink($temp);}
   }
   if(!$rollbackOk)throw new RuntimeException('Falha crítica: gravação e reversão incompletas. Restaurar backup.',0,$e);
   throw $e;
  }
  return true;
 });
}
ensure_data();
