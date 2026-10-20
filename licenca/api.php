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
  if(!$sessionOk){error_log('[UniGestor] me session invalid: has_user='.(empty($_SESSION['user_id'])?'0':'1').' has_restaurant='.(empty($_SESSION['restaurant_id'])?'0':'1').' cookie='.(isset($_COOKIE[session_name()])?'1':'0'));ug_end_session();outj(['ok'=>false,'erro'=>'Sessão expirada ou revogada.'],401);}
  $u=ug_user_by_session();
  if(!$u||!ug_restaurant_is_active($_SESSION['restaurant_id']??'')){ug_end_session();outj(['ok'=>false,'erro'=>'Sessão inválida.'],401);}
  $lic=license_for_restaurant($_SESSION['restaurant_id']);
  if(!$lic||status_license($lic)!=='ATIVA'){ug_end_session();outj(['ok'=>false,'erro'=>'Licença inválida.'],401);}
  outj(['ok'=>true,'user'=>ug_user_payload($u),'modules'=>ug_module_state($_SESSION['restaurant_id'],$u),
    'restaurant'=>['id'=>$_SESSION['restaurant_id'],'name'=>$lic['establishment']??''],
    'license'=>['status'=>'ATIVA','expires_at'=>$lic['expires_at']??null,'days_left'=>days_left($lic),'version'=>$lic['version']??null]]);
}
// Revalidação de senha para operações sensíveis sem trocar a sessão atual.
if($action==='authorize'){
  if($_SERVER['REQUEST_METHOD']!=='POST')outj(['ok'=>false,'erro'=>'Método inválido.'],405);
  start_app();
  try{$valid=ug_session_valid();}catch(Throwable $e){$valid=false;}
  if(!$valid)outj(['ok'=>false,'erro'=>'Sessão expirada. Entre novamente no UniGestor.'],401);
  $input=json_decode(file_get_contents('php://input'),true);
  if(!is_array($input))$input=[];
  $login=trim((string)($input['login']??''));
  $senha=(string)($input['senha']??'');
  if($login===''||$senha==='')outj(['ok'=>false,'erro'=>'Informe usuário e senha.'],400);
  if(!ug_login_rate_check($login))outj(['ok'=>false,'erro'=>'Muitas tentativas. Aguarde.'],429);
  $actor=ug_user_by_session();
  if(!$actor)outj(['ok'=>false,'erro'=>'Sessão inválida.'],401);
  $rid=(string)($_SESSION['restaurant_id']??'');
  $matches=[];
  foreach(read_json(USERS_FILE,[]) as $candidate)
    if(is_array($candidate)&&strtolower(trim((string)($candidate['login']??'')))===strtolower($login)&&
       (string)($candidate['restaurant_id']??'')===$rid)$matches[]=$candidate;
  $u=count($matches)===1?$matches[0]:null;
  if(!$u||!ug_is_active($u)||!password_verify($senha,(string)($u['password_hash']??''))){
    ug_login_rate($login);outj(['ok'=>false,'erro'=>'Usuário ou senha inválidos.'],401);
  }
  $role=strtoupper((string)($u['role']??''));
  if(!in_array($role,['ADMINISTRADOR','GERENTE','ADMIN','MANAGER'],true))
    outj(['ok'=>false,'erro'=>'Somente administrador ou gerente pode autorizar.'],403);
  ug_login_rate($login,true);
  outj(['ok'=>true,'user'=>ug_user_payload($u)]);
}
// Autorização de cancelamento por senha, restrita à empresa da sessão.
if($action==='authorize_password'){
  if($_SERVER['REQUEST_METHOD']!=='POST')outj(['ok'=>false,'erro'=>'Método inválido.'],405);
  start_app();
  try{$valid=ug_session_valid();}catch(Throwable $e){$valid=false;}
  if(!$valid)outj(['ok'=>false,'erro'=>'Sessão expirada.'],401);
  $actor=ug_user_by_session();
  $rid=(string)($_SESSION['restaurant_id']??'');
  if(!$actor||$rid==='')outj(['ok'=>false,'erro'=>'Sessão inválida.'],401);
  $input=json_decode(file_get_contents('php://input'),true);
  $senha=is_array($input)?(string)($input['senha']??''):'';
  if($senha==='')outj(['ok'=>false,'erro'=>'Informe a senha do fiscal ou administrador.'],400);
  $rateKey='cancel-password-'.$rid.'-'.(string)($actor['id']??'');
  if(!ug_login_rate_check($rateKey))outj(['ok'=>false,'erro'=>'Muitas tentativas. Aguarde.'],429);
  $matches=[];
  foreach(read_json(USERS_FILE,[]) as $candidate){
    if(!is_array($candidate)||(string)($candidate['restaurant_id']??'')!==$rid||!ug_is_active($candidate))continue;
    if(!in_array(strtoupper((string)($candidate['role']??'')),['ADMINISTRADOR','GERENTE','ADMIN','MANAGER','FISCAL'],true))continue;
    if(password_verify($senha,(string)($candidate['password_hash']??'')))$matches[]=$candidate;
  }
  if(count($matches)!==1){ug_login_rate($rateKey);outj(['ok'=>false,'erro'=>'Senha inválida ou autorização ambígua.'],401);}
  if(!ug_login_rate($rateKey,true))outj(['ok'=>false,'erro'=>'Falha no controle de tentativas.'],503);
  outj(['ok'=>true,'user'=>ug_user_payload($matches[0])]);
}
// Preferências compartilhadas por empresa, com revisão para evitar perda por concorrência.
if($action==='company_preferences'){
 if(!in_array($_SERVER['REQUEST_METHOD'],['GET','POST'],true))outj(['ok'=>false,'erro'=>'Método inválido.'],405);
 start_app();try{$valid=ug_session_valid();}catch(Throwable $e){$valid=false;}
 if(!$valid)outj(['ok'=>false,'erro'=>'Sessão inválida.'],401);
 $actor=ug_user_by_session();$rid=(string)($_SESSION['restaurant_id']??'');
 if(!$actor||$rid===''||!ug_restaurant_is_active($rid))outj(['ok'=>false,'erro'=>'Acesso negado.'],403);
 $lic=license_for_restaurant($rid);
 if(!$lic||status_license($lic)!=='ATIVA')outj(['ok'=>false,'erro'=>'Licença inativa.'],403);
 if($_SERVER['REQUEST_METHOD']==='POST'&&!in_array(strtoupper((string)($actor['role']??'')),['ADMINISTRADOR','GERENTE'],true))outj(['ok'=>false,'erro'=>'Sem permissão para alterar preferências.'],403);
 $dir=DATA_DIR.'/empresa-preferencias';$file=$dir.'/'.hash('sha256',$rid).'.json';
 if($_SERVER['REQUEST_METHOD']==='GET'){
  if(!is_file($file))outj(['ok'=>true,'disponivel'=>false,'revision'=>0]);
  $d=json_decode((string)@file_get_contents($file),true);
  if(!is_array($d))outj(['ok'=>false,'erro'=>'Preferências indisponíveis.'],503);
  outj(['ok'=>true,'disponivel'=>true,'revision'=>$d['revision']??0,'preferencias'=>$d['preferencias']??[]]);
 }
 $input=json_decode((string)file_get_contents('php://input'),true);
 $color=$input['preferencias']['cor_frente']??null;
 if(!is_string($color)||!preg_match('/^#[0-9a-fA-F]{6}$/D',$color))outj(['ok'=>false,'erro'=>'Cor inválida.'],400);
 $expected=$input['revision']??null;
 if(!is_int($expected)||$expected<0)outj(['ok'=>false,'erro'=>'Revisão obrigatória.'],400);
 if(!is_dir($dir)&&!mkdir($dir,0750,true)&&!is_dir($dir))outj(['ok'=>false,'erro'=>'Armazenamento indisponível.'],503);
 $fp=@fopen($file,'c+');if(!$fp)outj(['ok'=>false,'erro'=>'Armazenamento indisponível.'],503);
 try{
  if(!flock($fp,LOCK_EX))outj(['ok'=>false,'erro'=>'Bloqueio indisponível.'],503);
  rewind($fp);$old=stream_get_contents($fp);$current=$old?json_decode($old,true):[];
  $revision=(int)($current['revision']??0);
  if($revision!==$expected)outj(['ok'=>false,'erro'=>'Preferências alteradas em outro aparelho. Atualize antes de salvar.','revision'=>$revision],409);
  $data=['revision'=>$revision+1,'preferencias'=>['cor_frente'=>$color],'atualizado_em'=>gmdate('c')];
  $encoded=json_encode($data,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
  rewind($fp);ftruncate($fp,0);fwrite($fp,$encoded);fflush($fp);
 }finally{flock($fp,LOCK_UN);fclose($fp);}
 outj(['ok'=>true,'revision'=>$revision+1]);
}
// Catálogo compartilhado por empresa. Publicação inicial explícita para proteger o estoque local.
if($action==='stock_catalog'){
  if(!in_array($_SERVER['REQUEST_METHOD'],['GET','POST'],true))outj(['ok'=>false,'erro'=>'Método inválido.'],405);
  start_app();
  try{$valid=ug_session_valid();}catch(Throwable $e){$valid=false;}
  if(!$valid)outj(['ok'=>false,'erro'=>'Sessão inválida.'],401);
  $actor=ug_user_by_session();
  $rid=(string)($_SESSION['restaurant_id']??'');
  if(!$actor||$rid===''||!ug_restaurant_is_active($rid))outj(['ok'=>false,'erro'=>'Acesso negado.'],403);
  $lic=license_for_restaurant($rid);
  if(!$lic||status_license($lic)!=='ATIVA')outj(['ok'=>false,'erro'=>'Licença inativa.'],403);
  if($_SERVER['REQUEST_METHOD']==='POST'&&!in_array(strtoupper((string)($actor['role']??'')),['ADMINISTRADOR','GERENTE'],true))
    outj(['ok'=>false,'erro'=>'Somente gerente ou administrador pode publicar o estoque.'],403);
  $dir=DATA_DIR.'/empresa-estoque';
  $file=$dir.'/'.hash('sha256',$rid).'.json';
  if($_SERVER['REQUEST_METHOD']==='GET'){
    if(!is_file($file))outj(['ok'=>true,'disponivel'=>false,'produtos'=>[]]);
    $raw=@file_get_contents($file);
    if($raw===false)outj(['ok'=>false,'erro'=>'Falha ao ler estoque.'],503);
    $data=json_decode($raw,true);
    if(!is_array($data)||!isset($data['produtos'])||!is_array($data['produtos']))outj(['ok'=>false,'erro'=>'Estoque inválido.'],503);
    outj(['ok'=>true,'disponivel'=>true,'produtos'=>$data['produtos'],'atualizado_em'=>$data['atualizado_em']??null]);
  }
  $raw=file_get_contents('php://input');
  if(strlen($raw)>3000000)outj(['ok'=>false,'erro'=>'Estoque excede limite.'],413);
  $input=json_decode($raw,true);
  $produtos=$input['produtos']??null;
  if(!is_array($produtos)||!array_is_list($produtos)||!count($produtos)||count($produtos)>10000)
    outj(['ok'=>false,'erro'=>'Informe uma lista não vazia de produtos.'],400);
  foreach($produtos as $p){
    if(!is_array($p)||!is_string($p['nome']??null)||trim($p['nome'])===''||strlen($p['nome'])>300)
      outj(['ok'=>false,'erro'=>'Produto inválido.'],400);
  }
  if(!is_dir($dir)&&!mkdir($dir,0750,true)&&!is_dir($dir))outj(['ok'=>false,'erro'=>'Armazenamento indisponível.'],503);
  $fp=@fopen($file,'c+');
  if(!$fp)outj(['ok'=>false,'erro'=>'Estoque indisponível.'],503);
  try{
    if(!flock($fp,LOCK_EX))outj(['ok'=>false,'erro'=>'Falha de bloqueio.'],503);
    rewind($fp);$old=stream_get_contents($fp);
    if(trim($old)!==''&&!empty(json_decode($old,true)['produtos']))
      outj(['ok'=>false,'erro'=>'Já existe estoque no servidor. Publicação inicial bloqueada para evitar sobrescrita.'],409);
    $encoded=json_encode(['produtos'=>$produtos,'atualizado_em'=>gmdate('c')],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
    rewind($fp);ftruncate($fp,0);fwrite($fp,$encoded);fflush($fp);
  }finally{flock($fp,LOCK_UN);fclose($fp);}
  outj(['ok'=>true,'quantidade'=>count($produtos)]);
}
// Atualização pontual de preço: não substitui quantidades nem outros produtos.
if($action==='stock_price'){
 if(!in_array($_SERVER['REQUEST_METHOD'],['POST'],true))outj(['ok'=>false,'erro'=>'Método inválido.'],405);
 start_app();try{$valid=ug_session_valid();}catch(Throwable $e){$valid=false;}
 if(!$valid)outj(['ok'=>false,'erro'=>'Sessão inválida.'],401);
 $actor=ug_user_by_session();$rid=(string)($_SESSION['restaurant_id']??'');
 if(!$actor||$rid===''||!ug_restaurant_is_active($rid))outj(['ok'=>false,'erro'=>'Acesso negado.'],403);
 $lic=license_for_restaurant($rid);
 if(!$lic||status_license($lic)!=='ATIVA')outj(['ok'=>false,'erro'=>'Licença inativa.'],403);
 if(!in_array(strtoupper((string)($actor['role']??'')),['ADMINISTRADOR','GERENTE'],true))outj(['ok'=>false,'erro'=>'Sem permissão para alterar preço.'],403);
 $in=json_decode((string)file_get_contents('php://input'),true);
 $nome=trim((string)($in['nome']??''));$preco=$in['preco']??null;
 if($nome===''||strlen($nome)>300||!is_numeric($preco)||!is_finite((float)$preco)||(float)$preco<=0)outj(['ok'=>false,'erro'=>'Produto ou preço inválido.'],400);
 $file=DATA_DIR.'/empresa-estoque/'.hash('sha256',$rid).'.json';
 $fp=@fopen($file,'r+');if(!$fp)outj(['ok'=>false,'erro'=>'Publique o catálogo da empresa antes de sincronizar preços.'],409);
 try{
  if(!flock($fp,LOCK_EX))outj(['ok'=>false,'erro'=>'Bloqueio indisponível.'],503);
  rewind($fp);$d=json_decode((string)stream_get_contents($fp),true);
  if(!is_array($d)||!is_array($d['produtos']??null))outj(['ok'=>false,'erro'=>'Catálogo inválido.'],503);
  $matches=0;
  foreach($d['produtos'] as &$p){if(is_array($p)&&mb_strtolower((string)($p['nome']??''))===mb_strtolower($nome)){$p['preco']=(float)$preco;$matches++;}}unset($p);
  if($matches!==1)outj(['ok'=>false,'erro'=>'Produto não localizado de forma única no catálogo publicado.'],409);
  $d['atualizado_em']=gmdate('c');
  $encoded=json_encode($d,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
  rewind($fp);ftruncate($fp,0);fwrite($fp,$encoded);fflush($fp);
 }finally{flock($fp,LOCK_UN);fclose($fp);}
 outj(['ok'=>true,'preco'=>(float)$preco]);
}
// Backup individual de vendas da empresa autenticada.
// O backup administrativo geral permanece exclusivo do Painel Master.
if($action==='company_backup'){
  if($_SERVER['REQUEST_METHOD']!=='GET')outj(['ok'=>false,'erro'=>'Método inválido.'],405);
  start_app();
  try{$valid=ug_session_valid();}catch(Throwable $e){$valid=false;}
  if(!$valid)outj(['ok'=>false,'erro'=>'Sessão inválida.'],401);
  $actor=ug_user_by_session();
  $rid=(string)($_SESSION['restaurant_id']??'');
  if(!$actor||$rid===''||!ug_restaurant_is_active($rid))outj(['ok'=>false,'erro'=>'Acesso negado.'],403);
  if(!in_array((string)($actor['role']??''),['ADMINISTRADOR','GERENTE'],true))
    outj(['ok'=>false,'erro'=>'Somente administrador ou gerente pode baixar backup.'],403);
  $lic=license_for_restaurant($rid);
  if(!$lic||status_license($lic)!=='ATIVA')outj(['ok'=>false,'erro'=>'Licença inativa.'],403);
  if(!class_exists('ZipArchive'))outj(['ok'=>false,'erro'=>'Serviço de backup indisponível.'],503);
  $salesFile=DATA_DIR.'/empresa-vendas/'.hash('sha256',$rid).'.json';
  $sales=[];
  if(is_file($salesFile)){
    $fp=@fopen($salesFile,'rb');
    if(!$fp)outj(['ok'=>false,'erro'=>'Leitura de vendas indisponível.'],503);
    try{
      if(!flock($fp,LOCK_SH))throw new RuntimeException('lock');
      $raw=stream_get_contents($fp);
      $sales=json_decode($raw,true);
      if(!is_array($sales)||!array_is_list($sales))throw new RuntimeException('invalid sales');
    }catch(Throwable $e){fclose($fp);outj(['ok'=>false,'erro'=>'Não foi possível ler as vendas.'],503);}
    fclose($fp);
  }
  $users=[];
  foreach(read_json(USERS_FILE,[]) as $u)if((string)($u['restaurant_id']??'')===$rid)
    $users[]=['id'=>$u['id']??null,'name'=>$u['name']??'','login'=>$u['login']??'','role'=>$u['role']??'USUARIO','active'=>$u['active']??true];
  $manifest=['format'=>'unigestor-company-backup-v1','restaurant_id'=>$rid,'created_at'=>date('c'),
    'contents'=>['sales','users_metadata'],'note'=>'Backup individual: vendas centrais e identificacao de usuarios; demais modulos ainda nao centralizados.'];
  $temp=tempnam(sys_get_temp_dir(),'ug_company_');
  if($temp===false)outj(['ok'=>false,'erro'=>'Backup indisponível.'],503);
  $zip=new ZipArchive();
  try{
    if($zip->open($temp,ZipArchive::OVERWRITE)!==true)throw new RuntimeException('zip');
    foreach(['manifest.json'=>$manifest,'vendas.json'=>$sales,'usuarios.json'=>$users] as $name=>$value){
      $json=json_encode($value,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
      if(!$zip->addFromString($name,$json))throw new RuntimeException('zip file');
    }
    if(!$zip->close())throw new RuntimeException('zip close');
    header('Content-Type: application/zip');
    header('Content-Disposition: attachment; filename="UniGestor-empresa-'.substr(hash('sha256',$rid),0,12).'-'.date('Ymd-His').'.zip"');
    header('Content-Length: '.filesize($temp));
    header('Cache-Control: no-store, private');
    readfile($temp);
  }catch(Throwable $e){error_log('company_backup: '.$e->getMessage());if(!headers_sent())http_response_code(503);}
  finally{@unlink($temp);}
  exit;
}
// Cadastro de clientes por empresa, isolado e protegido por sessao.
if(in_array($action,['customers_list','customers_save','customers_delete'],true)){
 start_app();
 try{$valid=ug_session_valid();}catch(Throwable $e){$valid=false;}
 if(!$valid)outj(['ok'=>false,'erro'=>'Sessão inválida.'],401);
 $actor=ug_user_by_session();$rid=(string)($_SESSION['restaurant_id']??'');
 if(!$actor||!ug_restaurant_is_active($rid))outj(['ok'=>false,'erro'=>'Acesso negado.'],403);
 $lic=license_for_restaurant($rid);
 if(!$lic||status_license($lic)!=='ATIVA')outj(['ok'=>false,'erro'=>'Licença inativa.'],403);
 $perms=ug_effective_permissions($actor);
 if(!array_intersect(['PDV/Vendas','Caixa','Clientes'],$perms)&&!in_array(($actor['role']??''),['ADMINISTRADOR','GERENTE'],true))outj(['ok'=>false,'erro'=>'Sem permissão.'],403);
 ensure_data();$dir=DATA_DIR.'/empresa-clientes';
 if(!is_dir($dir)&&!mkdir($dir,0750,true)&&!is_dir($dir))outj(['ok'=>false,'erro'=>'Armazenamento indisponível.'],503);
 $fp=@fopen($dir.'/'.hash('sha256',$rid).'.json','c+');
 if(!$fp)outj(['ok'=>false,'erro'=>'Armazenamento indisponível.'],503);
 try{
  if(!flock($fp,LOCK_EX))throw new RuntimeException('lock');
  rewind($fp);$raw=stream_get_contents($fp);$rows=$raw?json_decode($raw,true):[];
  if(!is_array($rows)||!array_is_list($rows))throw new RuntimeException('dados inválidos');
  if($action==='customers_list'){flock($fp,LOCK_UN);fclose($fp);outj(['ok'=>true,'customers'=>$rows,'restaurant_id'=>$rid]);}
  if(($_SERVER['REQUEST_METHOD']??'')!=='POST')outj(['ok'=>false,'erro'=>'Método inválido.'],405);
  $body=file_get_contents('php://input');if(strlen($body)>8192)outj(['ok'=>false,'erro'=>'Dados excedem limite.'],413);
  $data=json_decode($body,true);if(!is_array($data))outj(['ok'=>false,'erro'=>'Dados inválidos.'],400);
  $id=trim((string)($data['id']??''));
  if(!preg_match('/^[a-zA-Z0-9_-]{6,100}$/D',$id))outj(['ok'=>false,'erro'=>'Identificador inválido.'],400);
  $found=-1;foreach($rows as $i=>$c)if(($c['id']??'')===$id){$found=$i;break;}
  if($action==='customers_delete'){
   if($found>=0)array_splice($rows,$found,1);
  }else{
   $nome=trim((string)($data['nome']??''));
   $limite=(float)($data['creditoLimite']??0);
   if($nome===''||strlen($nome)>320||!is_finite($limite)||$limite<0||$limite>10000000)outj(['ok'=>false,'erro'=>'Nome ou limite inválido.'],400);
   $item=['id'=>$id,'nome'=>$nome,'telefone'=>substr((string)($data['telefone']??''),0,80),'endereco'=>substr((string)($data['endereco']??''),0,300),'cpf'=>substr((string)($data['cpf']??''),0,32),'creditoLimite'=>round($limite,2),'ativo'=>($data['ativo']??true)!==false];
   if($found>=0)$rows[$found]=$item;else $rows[]=$item;
  }
  $json=json_encode($rows,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
  rewind($fp);if(fwrite($fp,$json)!==strlen($json)||!ftruncate($fp,strlen($json))||!fflush($fp))throw new RuntimeException('write');
  flock($fp,LOCK_UN);fclose($fp);outj(['ok'=>true,'customers'=>$rows]);
 }catch(Throwable $e){error_log('[UniGestor] clientes: '.$e->getMessage());if(is_resource($fp))fclose($fp);outj(['ok'=>false,'erro'=>'Falha no cadastro central.'],503);}
}
// Registro central de vendas: um arquivo independente por empresa, com trava
// exclusiva e identificador idempotente. Nunca aceita restaurant_id do navegador.
if(in_array($action,['sales_list','sales_create'],true)){
  start_app();
  try{$valid=ug_session_valid();}catch(Throwable $e){$valid=false;}
  if(!$valid)outj(['ok'=>false,'erro'=>'Sessão inválida.'],401);
  $actor=ug_user_by_session();
  $rid=(string)($_SESSION['restaurant_id']??'');
  if(!$actor||!ug_restaurant_is_active($rid))outj(['ok'=>false,'erro'=>'Acesso negado.'],403);
  $lic=license_for_restaurant($rid);
  if(!$lic||status_license($lic)!=='ATIVA')outj(['ok'=>false,'erro'=>'Licença inativa.'],403);
  $perms=ug_effective_permissions($actor);
  if(!array_intersect(['PDV/Vendas','Caixa'], $perms) && !in_array(($actor['role']??''),['ADMINISTRADOR','GERENTE'],true))
    outj(['ok'=>false,'erro'=>'Sem permissão de vendas.'],403);
  ensure_data();
  $dir=DATA_DIR.'/empresa-vendas';
  if(!is_dir($dir)&&!mkdir($dir,0750,true)&&!is_dir($dir))outj(['ok'=>false,'erro'=>'Armazenamento indisponível.'],503);
  $file=$dir.'/'.hash('sha256',$rid).'.json';
  $fp=@fopen($file,'c+');
  if(!$fp)outj(['ok'=>false,'erro'=>'Armazenamento indisponível.'],503);
  try{
    if(!flock($fp,LOCK_EX))throw new RuntimeException('lock');
    rewind($fp);$raw=stream_get_contents($fp);
    $rows=$raw?json_decode($raw,true):[];
    if(!is_array($rows)||!array_is_list($rows))throw new RuntimeException('dados inválidos');
    if($action==='sales_list'){
      if($_SERVER['REQUEST_METHOD']!=='GET')outj(['ok'=>false,'erro'=>'Método inválido.'],405);
      flock($fp,LOCK_UN);fclose($fp);
      outj(['ok'=>true,'sales'=>$rows,'restaurant_id'=>$rid]);
    }
    if($_SERVER['REQUEST_METHOD']!=='POST')outj(['ok'=>false,'erro'=>'Método inválido.'],405);
    $body=file_get_contents('php://input');
    if(strlen($body)>32768)outj(['ok'=>false,'erro'=>'Venda excede tamanho permitido.'],413);
    $v=json_decode($body,true);
    if(!is_array($v)||!is_array($v['itens']??null)||!is_array($v['pagamentos']??null))
      outj(['ok'=>false,'erro'=>'Venda inválida.'],400);
    $id=trim((string)($v['id']??''));
    if(!preg_match('/^[a-zA-Z0-9_-]{5,100}$/D',$id))outj(['ok'=>false,'erro'=>'ID inválido.'],400);
    foreach($rows as $existing)if(($existing['id']??'')===$id){
      flock($fp,LOCK_UN);fclose($fp);outj(['ok'=>true,'id'=>$id,'duplicate'=>true]);
    }
    $v['usuario_id']=(string)$actor['id'];
    $v['usuario_nome']=(string)($actor['name']??$actor['login']??'');
    $v['usuario_login']=(string)($actor['login']??'');
    $v['registrado_em']=date('c');
    $v['total']=round((float)($v['total']??0),2);
    if($v['total']<0||$v['total']>100000000)outj(['ok'=>false,'erro'=>'Valor inválido.'],400);
    $rows[]=$v;
    $json=json_encode($rows,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
    rewind($fp);
    if(fwrite($fp,$json)!==strlen($json)||!ftruncate($fp,strlen($json))||!fflush($fp))throw new RuntimeException('write');
    flock($fp,LOCK_UN);fclose($fp);
    outj(['ok'=>true,'id'=>$id,'user'=>$v['usuario_nome']]);
  }catch(Throwable $e){
    error_log('[UniGestor] falha banco vendas: '.$e->getMessage());
    if(is_resource($fp))fclose($fp);
    outj(['ok'=>false,'erro'=>'Falha no armazenamento central.'],503);
  }
}
// Pedidos abertos por empresa: separados de vendas e protegidos por sessao/permissoes.
if(in_array($action,['orders_list','orders_upsert'],true)){
 start_app();
 try{$valid=ug_session_valid();}catch(Throwable $e){$valid=false;}
 if(!$valid)outj(['ok'=>false,'erro'=>'Sessão inválida.'],401);
 $actor=ug_user_by_session();
 $rid=(string)($_SESSION['restaurant_id']??'');
 if(!$actor||!ug_restaurant_is_active($rid))outj(['ok'=>false,'erro'=>'Acesso negado.'],403);
 $lic=license_for_restaurant($rid);
 if(!$lic||status_license($lic)!=='ATIVA')outj(['ok'=>false,'erro'=>'Licença inativa.'],403);
 $perms=ug_effective_permissions($actor);
 if(!array_intersect(['PDV/Vendas','Caixa'], $perms) && !in_array(($actor['role']??''),['ADMINISTRADOR','GERENTE'],true))
   outj(['ok'=>false,'erro'=>'Sem permissão de pedidos.'],403);
 $dir=DATA_DIR.'/empresa-pedidos';
 if(!is_dir($dir)&&!mkdir($dir,0750,true)&&!is_dir($dir))outj(['ok'=>false,'erro'=>'Armazenamento indisponível.'],503);
 $file=$dir.'/'.hash('sha256',$rid).'.json';
 $fp=@fopen($file,'c+');
 if(!$fp)outj(['ok'=>false,'erro'=>'Armazenamento indisponível.'],503);
 try{
  if(!flock($fp,LOCK_EX))throw new RuntimeException('lock');
  rewind($fp);$raw=stream_get_contents($fp);
  $rows=$raw?json_decode($raw,true):[];
  if(!is_array($rows)||!array_is_list($rows))throw new RuntimeException('dados inválidos');
  if($action==='orders_list'){
   if(($_SERVER['REQUEST_METHOD']??'GET')!=='GET')outj(['ok'=>false,'erro'=>'Método inválido.'],405);
   flock($fp,LOCK_UN);fclose($fp);
   outj(['ok'=>true,'orders'=>$rows,'restaurant_id'=>$rid]);
  }
  if(($_SERVER['REQUEST_METHOD']??'GET')!=='POST')outj(['ok'=>false,'erro'=>'Método inválido.'],405);
  $body=file_get_contents('php://input');
  if(strlen($body)>32768)outj(['ok'=>false,'erro'=>'Pedido excede tamanho permitido.'],413);
  $v=json_decode($body,true);
  if(!is_array($v)||!is_array($v['itens']??null)||!array_is_list($v['itens'])||count($v['itens'])<1||count($v['itens'])>200)
    outj(['ok'=>false,'erro'=>'Pedido inválido.'],400);
  $id=trim((string)($v['id']??''));
  if(!preg_match('/^[a-zA-Z0-9_-]{5,100}$/D',$id))outj(['ok'=>false,'erro'=>'ID inválido.'],400);
  $v['id']=$id;
  $v['status']='ABERTO';
  $v['usuario_id']=(string)$actor['id'];
  $v['usuario_nome']=(string)($actor['name']??$actor['login']??'');
  $v['registrado_em']=date('c');
  $v['total']=round((float)($v['total']??0),2);
  if(!is_finite($v['total'])||$v['total']<0||$v['total']>100000000)outj(['ok'=>false,'erro'=>'Valor inválido.'],400);
  foreach($v['itens'] as $item){
   if(!is_array($item)||!is_numeric($item['qtd']??null)||!is_numeric($item['preco']??null)||
      (float)$item['qtd']<=0||(float)$item['preco']<0)outj(['ok'=>false,'erro'=>'Item inválido.'],400);
  }
  foreach($rows as $existing)if(($existing['id']??'')===$id){
   flock($fp,LOCK_UN);fclose($fp);
   outj(['ok'=>true,'id'=>$id,'duplicate'=>true]);
  }
  $rows[]=$v;
  $json=json_encode($rows,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
  rewind($fp);
  if(fwrite($fp,$json)!==strlen($json)||!ftruncate($fp,strlen($json))||!fflush($fp))throw new RuntimeException('write');
  flock($fp,LOCK_UN);fclose($fp);
  outj(['ok'=>true,'id'=>$id,'user'=>$v['usuario_nome']]);
 }catch(Throwable $e){
  error_log('[UniGestor] falha banco pedidos: '.$e->getMessage());
  if(is_resource($fp))fclose($fp);
  outj(['ok'=>false,'erro'=>'Falha no armazenamento central de pedidos.'],503);
 }
}
// Gestão de funcionários restrita ao administrador/gerente da própria empresa.
if(in_array($action,['users_list','users_create','users_update'],true)){
  start_app();
  try{$valid=ug_session_valid();}catch(Throwable $e){$valid=false;}
  if(!$valid){error_log('[UniGestor] users session invalid: has_user='.(empty($_SESSION['user_id'])?'0':'1').' has_restaurant='.(empty($_SESSION['restaurant_id'])?'0':'1').' cookie='.(isset($_COOKIE[session_name()])?'1':'0').' session_active='.(session_status()===PHP_SESSION_ACTIVE?'1':'0'));outj(['ok'=>false,'erro'=>'Sessão inválida.'],401);}
  $actor=ug_user_by_session();
  $rid=(string)($_SESSION['restaurant_id']??'');
  if(!$actor||!ug_restaurant_is_active($rid)||!in_array(($actor['role']??''),['ADMINISTRADOR','GERENTE'],true)
    ||!in_array('Usuários/Permissões',ug_effective_permissions($actor),true))
    outj(['ok'=>false,'erro'=>'Sem permissão para administrar usuários.'],403);
  $lic=license_for_restaurant($rid);
  if(!$lic||status_license($lic)!=='ATIVA')outj(['ok'=>false,'erro'=>'Licença inativa.'],403);
  $users=read_json(USERS_FILE,[]);
  if($action==='users_list'){
    if($_SERVER['REQUEST_METHOD']!=='GET')outj(['ok'=>false,'erro'=>'Método inválido.'],405);
    $list=[];
    foreach($users as $u)if(($u['restaurant_id']??'')===$rid)$list[]=[
      'id'=>$u['id'],'name'=>$u['name'],'login'=>$u['login'],'role'=>$u['role']??'USUARIO',
      'active'=>($u['active']??true)===true,'permissions'=>ug_user_permissions($u)];
    outj(['ok'=>true,'users'=>$list,'modules'=>ug_company_modules($rid)]);
  }
  if($_SERVER['REQUEST_METHOD']!=='POST')outj(['ok'=>false,'erro'=>'Método inválido.'],405);
  $input=json_decode(file_get_contents('php://input'),true);
  if(!is_array($input))outj(['ok'=>false,'erro'=>'JSON inválido.'],400);
  $name=trim((string)($input['name']??''));
  $role=strtoupper(trim((string)($input['role']??'USUARIO')));
  if(!in_array($role,['ADMINISTRADOR','GERENTE','VENDEDOR','GARCOM','CAIXA','USUARIO'],true))
    outj(['ok'=>false,'erro'=>'Perfil inválido.'],400);
  if($role==='ADMINISTRADOR'&&($actor['role']??'')!=='ADMINISTRADOR')
    outj(['ok'=>false,'erro'=>'Somente administrador pode definir outro administrador.'],403);
  $requested=$input['permissions']??[];
  if(!is_array($requested)||!array_is_list($requested))outj(['ok'=>false,'erro'=>'Permissões inválidas.'],400);
  $perms=ug_valid_modules($requested);
  if(count($perms)!==count(array_unique($requested))||array_diff($perms,ug_company_modules($rid)))
    outj(['ok'=>false,'erro'=>'Selecione apenas módulos contratados.'],400);
  if($name===''||mb_strlen($name)>120)outj(['ok'=>false,'erro'=>'Nome inválido.'],400);
  if($action==='users_create'){
    $login=trim((string)($input['login']??''));
    $password=(string)($input['password']??'');
    if(!preg_match('/^[a-zA-Z0-9_.@-]{3,80}$/',$login)||strlen($password)<8)
      outj(['ok'=>false,'erro'=>'Login inválido ou senha menor que 8 caracteres.'],400);
    foreach($users as $u)if(strcasecmp(trim((string)($u['login']??'')),$login)===0)
      outj(['ok'=>false,'erro'=>'Login já cadastrado.'],409);
    $users[]=['id'=>'USR-'.strtoupper(bin2hex(random_bytes(5))),'restaurant_id'=>$rid,
      'name'=>$name,'login'=>$login,'password_hash'=>password_hash($password,PASSWORD_DEFAULT),
      'role'=>$role,'active'=>true,'created_at'=>date('c'),'permissions'=>$perms];
  }else{
    $id=(string)($input['id']??'');$found=false;
    foreach($users as &$u){
      if(($u['id']??'')!==$id||($u['restaurant_id']??'')!==$rid)continue;
      if(($u['role']??'')==='ADMINISTRADOR'&&($actor['role']??'')!=='ADMINISTRADOR')
        outj(['ok'=>false,'erro'=>'Gerente não pode editar administrador.'],403);
      if($id===(string)$actor['id']&&(!($input['active']??true)||$role!=='ADMINISTRADOR'&&$actor['role']==='ADMINISTRADOR'))
        outj(['ok'=>false,'erro'=>'Não é permitido desativar ou rebaixar sua própria conta.'],400);
      $u['name']=$name;$u['role']=$role;$u['permissions']=$perms;
      $u['active']=($input['active']??true)===true;
      if(!empty($input['password'])){
        if(strlen((string)$input['password'])<8)outj(['ok'=>false,'erro'=>'Senha menor que 8 caracteres.'],400);
        $u['password_hash']=password_hash((string)$input['password'],PASSWORD_DEFAULT);
      }
      $found=true;break;
    }
    unset($u);
    if(!$found)outj(['ok'=>false,'erro'=>'Usuário não encontrado nesta empresa.'],404);
  }
  write_json(USERS_FILE,$users);
  outj(['ok'=>true,'message'=>'Usuário salvo com sucesso.']);
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
