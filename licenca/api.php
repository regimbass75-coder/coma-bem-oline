<?php
require __DIR__.'/lib.php';
require_once __DIR__.'/ug_permissions.php';
require_once __DIR__.'/ug_modules.php';
require_once __DIR__.'/ug_login_rate.php';
require_once __DIR__.'/ug_sessions.php';
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
function outj($data,$code=200){http_response_code($code);echo json_encode($data,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);exit;}
function ug_is_active($record){return is_array($record) && ($record['active']??true)===true;}
function ug_restaurant_is_active($rid){
  foreach(read_json(RESTAURANTS_FILE,[]) as $r){
    if((string)($r['id']??'')===(string)$rid)
      return strtoupper((string)($r['status']??''))==='ATIVO';
  }
  return false;
}
function ug_user_by_session(){
  if(empty($_SESSION['user_id'])||empty($_SESSION['restaurant_id']))return null;
  foreach(read_json(USERS_FILE,[]) as $u)
    if((string)($u['id']??'')===(string)$_SESSION['user_id'] &&
       (string)($u['restaurant_id']??'')===(string)$_SESSION['restaurant_id'] &&
       ug_is_active($u)) return $u;
  return null;
}
function ug_end_session(){
  try{ug_session_release();}catch(Throwable $e){error_log('Falha ao liberar sessão: '.$e->getMessage());}
  $_SESSION=[];
  if(ini_get('session.use_cookies')){
    $p=session_get_cookie_params();
    setcookie(session_name(),'',[
      'expires'=>time()-3600,'path'=>$p['path'],'domain'=>$p['domain'],
      'secure'=>$p['secure'],'httponly'=>$p['httponly'],'samesite'=>$p['samesite']??'Lax'
    ]);
  }
  session_destroy();
}
function ug_user_payload($u){
  return ['id'=>$u['id']??null,'name'=>$u['name']??'','login'=>$u['login']??'',
    'role'=>$u['role']??'USUARIO','permissions'=>ug_effective_permissions($u)];
}
$action=strtolower(trim((string)($_GET['action']??$_POST['action']??'')));
if($action==='login'){
  if($_SERVER['REQUEST_METHOD']!=='POST')outj(['ok'=>false,'erro'=>'Use POST para entrar.'],405);
  start_app();
  // Ao trocar de conta, liberar a vaga anterior antes de limpar a identidade.
  if(!empty($_SESSION['user_id']) && !empty($_SESSION['restaurant_id'])){
    try{ug_session_release();}catch(Throwable $e){outj(['ok'=>false,'erro'=>'Não foi possível encerrar a sessão anterior.'],503);}
  }
  unset($_SESSION['user_id'],$_SESSION['restaurant_id'],$_SESSION['role']);
  $input=json_decode(file_get_contents('php://input'),true);
  if(!is_array($input))$input=$_POST;
  $login=trim((string)($input['login']??''));
  $senha=(string)($input['senha']??'');
  if($login===''||$senha==='')outj(['ok'=>false,'erro'=>'Informe usuário e senha.'],400);
  if(!ug_login_rate_check($login))outj(['ok'=>false,'erro'=>'Muitas tentativas. Aguarde 15 minutos.'],429);
  $matches=[];
  foreach(read_json(USERS_FILE,[]) as $candidate)
    if(is_array($candidate) && strtolower(trim((string)($candidate['login']??'')))===strtolower($login))$matches[]=$candidate;
  if(count($matches)!==1){ug_login_rate($login);outj(['ok'=>false,'erro'=>'Usuário ou senha inválidos.'],401);}
  $u=$matches[0];
  if(!$u||!ug_is_active($u)||!password_verify($senha,(string)($u['password_hash']??'')))
    {ug_login_rate($login);outj(['ok'=>false,'erro'=>'Usuário ou senha inválidos.'],401);}
  $rid=(string)($u['restaurant_id']??'');
  if($rid===''||!ug_restaurant_is_active($rid))outj(['ok'=>false,'erro'=>'Restaurante inativo ou inexistente.'],403);
  $lic=license_for_restaurant($rid);
  if(!$lic)outj(['ok'=>false,'erro'=>'Licença não encontrada.'],403);
  $st=status_license($lic);
  if($st!=='ATIVA')outj(['ok'=>false,'erro'=>'Licença '.$st.'.','status'=>$st],403);
  if(!ug_login_rate($login,true))outj(['ok'=>false,'erro'=>'Falha no controle de tentativas.'],503);
  if(!session_regenerate_id(true))outj(['ok'=>false,'erro'=>'Falha ao renovar sessão.'],500);
  $restaurant=ug_restaurant_record($rid);
  try{$claimed=ug_session_claim($rid,(string)$u['id'],(int)($restaurant['access_limit']??1));}
  catch(Throwable $e){outj(['ok'=>false,'erro'=>'Controle de sessões indisponível.'],503);}
  if(!$claimed)outj(['ok'=>false,'erro'=>'Limite de acessos simultâneos atingido.'],403);
  $_SESSION['user_id']=$u['id'];$_SESSION['restaurant_id']=$rid;$_SESSION['role']=$u['role']??'USUARIO';
  outj(['ok'=>true,'user'=>ug_user_payload($u),'modules'=>ug_module_state($rid,$u),'restaurant'=>['id'=>$rid,'name'=>$lic['establishment']??''],
    'license'=>['status'=>$st,'expires_at'=>$lic['expires_at']??null,'days_left'=>days_left($lic),'version'=>$lic['version']??null]]);
}
if($action==='me'){
  start_app();
  try{$sessionOk=ug_session_valid();}catch(Throwable $e){$sessionOk=false;}
  if(!$sessionOk){ug_end_session();outj(['ok'=>false,'erro'=>'Sessão expirada ou revogada.'],401);}
  $u=ug_user_by_session();
  if(!$u||!ug_restaurant_is_active($_SESSION['restaurant_id']??'')){ug_end_session();outj(['ok'=>false,'erro'=>'Sessão inválida.'],401);}
  $lic=license_for_restaurant($_SESSION['restaurant_id']);
  if(!$lic||status_license($lic)!=='ATIVA'){ug_end_session();outj(['ok'=>false,'erro'=>'Licença inválida.'],401);}
  outj(['ok'=>true,'user'=>ug_user_payload($u),'modules'=>ug_module_state($_SESSION['restaurant_id'],$u),
    'restaurant'=>['id'=>$_SESSION['restaurant_id'],'name'=>$lic['establishment']??''],
    'license'=>['status'=>'ATIVA','expires_at'=>$lic['expires_at']??null,'days_left'=>days_left($lic),'version'=>$lic['version']??null]]);
}
if($action==='logout'){
  if($_SERVER['REQUEST_METHOD']!=='POST')outj(['ok'=>false,'erro'=>'Use POST para sair.'],405);
  start_app();ug_end_session();outj(['ok'=>true]);
}
$key=strtoupper(trim((string)($_GET['key']??$_POST['key']??'')));
if(!$key)outj(['ok'=>false,'status'=>'SEM_CHAVE'],400);
$found=null;foreach(read_json(LICENSE_FILE,[]) as $l)if(strtoupper((string)($l['key']??''))===$key){$found=$l;break;}
if(!$found)outj(['ok'=>false,'status'=>'INVALIDA'],404);
$st=status_license($found);
outj(['ok'=>$st==='ATIVA','status'=>$st,'expires_at'=>$found['expires_at']??null,'days_left'=>days_left($found),
'establishment'=>$found['establishment']??'','restaurant_id'=>$found['restaurant_id']??null,'version'=>$found['version']??null]);
