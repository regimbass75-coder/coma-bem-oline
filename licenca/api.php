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
