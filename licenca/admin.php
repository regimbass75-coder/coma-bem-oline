<?php
require __DIR__.'/lib.php'; require_admin();
if(empty($_SESSION['ug_master_csrf']) || !is_string($_SESSION['ug_master_csrf'])) $_SESSION['ug_master_csrf']=bin2hex(random_bytes(32));
function ug_master_csrf_field():string{return '<input type="hidden" name="ug_csrf" value="'.h($_SESSION['ug_master_csrf']).'">';}


$licenses=read_json(LICENSE_FILE,[]);
$restaurants=read_json(RESTAURANTS_FILE,[]);
$users=read_json(USERS_FILE,[]);
$flash=(string)($_SESSION['ug_master_flash']??'');
unset($_SESSION['ug_master_flash']);
function ug_limit($value){return max(1,min(500,(int)$value));}
function ug_price($value){$v=str_replace(',','.',trim((string)$value));return is_numeric($v)?round(max(0,(float)$v),2):0;}


$moduleOptions=[
 'PDV/Vendas','Mesas','Comandas','Caixa','Cozinha/KDS','Produtos','Grupos',
 'Clientes','Financeiro','Fiscal','Garçom Mobile','Delivery','Relatórios',
 'Usuários/Permissões','Configurações','Compras','Estoque','Comissões','Pedidos','Venda Externa'
];
$segments=[
 'COMERCIO'=>'Comércio geral',
 'RESTAURANTE'=>'Restaurante',
 'MERCANTIL'=>'Mercantil / Supermercado',
 'ROUPAS'=>'Loja de roupas',
 'CALCADOS'=>'Calçados',
 'ELETRONICOS'=>'Eletrônicos',
 'SERVICOS'=>'Serviços',
 'PERSONALIZADO'=>'Personalizado'
];
$defaults=[
 'COMERCIO'=>['PDV/Vendas','Caixa','Clientes','Produtos','Estoque','Financeiro','Relatórios'],
 'RESTAURANTE'=>['PDV/Vendas','Mesas','Comandas','Caixa','Cozinha/KDS','Produtos','Grupos','Clientes','Financeiro','Garçom Mobile','Delivery','Relatórios','Pedidos','Comissões'],
 'MERCANTIL'=>['PDV/Vendas','Caixa','Produtos','Estoque','Clientes','Compras','Financeiro','Relatórios'],
 'ROUPAS'=>['PDV/Vendas','Caixa','Produtos','Estoque','Clientes','Financeiro','Relatórios','Comissões'],
 'CALCADOS'=>['PDV/Vendas','Caixa','Produtos','Estoque','Clientes','Financeiro','Relatórios','Comissões'],
 'ELETRONICOS'=>['PDV/Vendas','Caixa','Produtos','Estoque','Clientes','Financeiro','Relatórios'],
 'SERVICOS'=>['PDV/Vendas','Caixa','Clientes','Financeiro','Relatórios']
];

if($_SERVER['REQUEST_METHOD']==='POST'){
 if(!isset($_POST['ug_csrf']) || !is_string($_POST['ug_csrf']) || !hash_equals($_SESSION['ug_master_csrf'],$_POST['ug_csrf'])) {http_response_code(403);exit('Requisição recusada: token CSRF inválido.');}
 $act=$_POST['act']??'';
 // Operações que não criam um conjunto usam o mesmo bloqueio global da criação.
 // Recarregar dentro do bloqueio impede perda de atualizações concorrentes.
 $ugLock=null;
 if($act!=='create'){
  $ugLock=@fopen(DATA_DIR.'/.master.lock','c');
  if(!$ugLock || !flock($ugLock,LOCK_EX)){http_response_code(503);exit('Bloqueio administrativo indisponível');}
  $licenses=read_json(LICENSE_FILE,[]);
  $restaurants=read_json(RESTAURANTS_FILE,[]);
  $users=read_json(USERS_FILE,[]);
 }
 try{

 if($act==='create'){
  $days=max(1,(int)($_POST['days']??30));
  $rid=restaurant_id(); $key=keygen(); $pass=temp_password();
  $name=trim($_POST['establishment']??''); $client=trim($_POST['client']??'');
  $segment=strtoupper(trim($_POST['segment']??'COMERCIO'));
  if(!isset($segments[$segment])) $segment='COMERCIO';
  $requestedMods=$_POST['modules']??[];
  $mods=is_array($requestedMods)?array_values(array_intersect($moduleOptions,$requestedMods)):[];
  if(!$mods) $mods=$defaults[$segment]??$defaults['COMERCIO'];

  $login=trim($_POST['login']??'');
  if($name===''||$client===''||$login===''||count(array_filter($users,fn($u)=>strtolower(trim((string)($u['login']??'')))===strtolower($login)))>0){
    $flash='Login vazio ou já cadastrado; empresa não criada.';
  }else{
  $newRestaurant=[
    'id'=>$rid,'name'=>$name,'client'=>$client,
    'document'=>trim($_POST['document']??''),'phone'=>trim($_POST['phone']??''),
    'address'=>trim($_POST['address']??''),'status'=>'ATIVO',
    'segment'=>$segment,'segment_name'=>$segments[$segment],
    'modules'=>$mods,'access_limit'=>ug_limit($_POST['access_limit']??1),'package_price'=>ug_price($_POST['package_price']??0),'created_at'=>date('c')
  ];
  $newLicense=[
    'key'=>$key,'restaurant_id'=>$rid,'client'=>$client,'establishment'=>$name,
    'created_at'=>date('c'),'expires_at'=>date('Y-m-d',strtotime("+$days days")),
    'blocked'=>false,'version'=>'v333','notes'=>trim($_POST['notes']??''),
    'history'=>[['at'=>date('c'),'action'=>"Criada por $days dias"]]
  ];
  $newUser=[
    'id'=>'USR-'.strtoupper(substr(bin2hex(random_bytes(5)),0,10)),
    'restaurant_id'=>$rid,'name'=>$client ?: $name,'login'=>$login,
    'password_hash'=>password_hash($pass,PASSWORD_DEFAULT),
    'role'=>'ADMINISTRADOR','active'=>true,'created_at'=>date('c'),
    'permissions'=>$mods
  ];
  try{ug_master_create_bundle($newRestaurant,$newLicense,$newUser);}
  catch(Throwable $e){$flash="Cadastro não concluído: ".$e->getMessage();$createFailed=true;}
  if(empty($createFailed))$flash="Empresa criada: $name | Segmento: {$segments[$segment]} | Chave: $key | Usuário: $login | Senha temporária: $pass";
  }
 }
  elseif($act==='update_package'){
   $rid=trim((string)($_POST['restaurant_id']??''));
   $segment=strtoupper(trim((string)($_POST['segment']??'COMERCIO')));
   if(!isset($segments[$segment])) $segment='COMERCIO';
   $requestedMods=$_POST['modules']??[];
  $mods=is_array($requestedMods)?array_values(array_intersect($moduleOptions,$requestedMods)):[];
   $found=false;
   foreach($restaurants as &$r){
     if(($r['id']??'')!==$rid) continue;
     $r['segment']=$segment;
     $r['segment_name']=$segments[$segment];
     $r['modules']=$mods;
     $r['access_limit']=ug_limit($_POST['access_limit']??1);
     $r['package_price']=ug_price($_POST['package_price']??0);
     $r['package_updated_at']=date('c');
     $found=true;
     break;
   }
   unset($r);
   if($found){write_json(RESTAURANTS_FILE,$restaurants);$flash='Pacote e módulos da empresa atualizados. Atenção: o bloqueio de sessões simultâneas exige integração com o login do UniGestor.';}
   else $flash='Empresa não encontrada. Nenhuma alteração realizada.';
  }
 elseif($act==='create_user'){
  $rid=trim($_POST['restaurant_id']??'');
  $name=trim($_POST['user_name']??'');
  $login=trim($_POST['user_login']??'');
  $pass=(string)($_POST['user_password']??'');
  $role=trim((string)($_POST['user_role']??'VENDEDOR'));
  if(!in_array($role,['ADMINISTRADOR','GERENTE','VENDEDOR','GARCOM','CAIXA','USUARIO'],true))$role='USUARIO';
  $requestedPerms=$_POST['permissions']??[];
  $perms=is_array($requestedPerms)?array_values(array_intersect($moduleOptions,$requestedPerms)):[];
  if($rid===''||$name===''||$login===''||strlen($pass)<8){
    $flash='Informe empresa, nome, login e senha com pelo menos 8 caracteres.';
  } elseif(count(array_filter($users,fn($u)=>strtolower(trim((string)($u['login']??'')))===strtolower($login)))>0){
    $flash='Este login já está cadastrado.';
  } else {
    $exists=array_values(array_filter($restaurants,fn($r)=>($r['id']??'')===$rid));
    if(!$exists || ($exists[0]['status']??'')!=='ATIVO'){$flash='Empresa inexistente ou inativa.';}
    else{
      $users[]=[
        'id'=>'USR-'.strtoupper(substr(bin2hex(random_bytes(5)),0,10)),
        'restaurant_id'=>$rid,'name'=>$name,'login'=>$login,
        'password_hash'=>password_hash($pass,PASSWORD_DEFAULT),
        'role'=>$role,'active'=>true,'created_at'=>date('c'),
        'permissions'=>$perms
      ];
      write_json(USERS_FILE,$users);
      $flash="Usuário $name criado com sucesso. Permissões: ".($perms?implode(', ',$perms):'nenhuma');
    }
  }
 }
 elseif($act==='update_user'){
  $uid=trim($_POST['user_id']??'');
  foreach($users as &$u){
    if(($u['id']??'')!==$uid) continue;
    $u['name']=trim($_POST['user_name']??$u['name']);
    $requestedRole=trim((string)($_POST['user_role']??$u['role']));
    if(in_array($requestedRole,['ADMINISTRADOR','GERENTE','VENDEDOR','GARCOM','CAIXA','USUARIO'],true))$u['role']=$requestedRole;
    $u['active']=isset($_POST['active']);
    $requestedPerms=$_POST['permissions']??[];
    $u['permissions']=is_array($requestedPerms)?array_values(array_intersect($moduleOptions,$requestedPerms)):[];
    if(strlen((string)($_POST['user_password']??''))>=8) $u['password_hash']=password_hash($_POST['user_password'],PASSWORD_DEFAULT);
    $flash="Permissões do usuário {$u['name']} atualizadas.";
    break;
  }
  unset($u);
  if($flash!=='')write_json(USERS_FILE,$users);
  else $flash='Usuário não encontrado; nenhuma alteração realizada.';
 }
 elseif(in_array($act,['extend','toggle','delete'],true)){
  $key=$_POST['key']??'';
  $licenseFound=false;
  foreach($licenses as &$l) if(($l['key']??'')===$key){
   $licenseFound=true;
   if($act==='extend'){ $days=max(1,(int)($_POST['days']??30)); $base=max(time(),strtotime(($l['expires_at']??date('Y-m-d')).' 23:59:59')); $l['expires_at']=date('Y-m-d',strtotime("+$days days",$base)); $l['blocked']=false; $l['history'][]=['at'=>date('c'),'action'=>"Renovada por $days dias"]; }
   if($act==='toggle'){ $l['blocked']=empty($l['blocked']); $l['history'][]=['at'=>date('c'),'action'=>$l['blocked']?'Bloqueada':'Desbloqueada']; }
   if($act==='delete') $l['_delete']=true;
  } unset($l);
  if($act==='delete') $licenses=array_values(array_filter($licenses,fn($x)=>empty($x['_delete'])));
  if($licenseFound){write_json(LICENSE_FILE,$licenses);$flash='Licença atualizada.';}
  else $flash='Licença não encontrada; nenhuma alteração realizada.';
 }
 }finally{if($ugLock){flock($ugLock,LOCK_UN);fclose($ugLock);}}
 // Após POST, redirecionar para GET para F5 não repetir bloqueio/desbloqueio.
 $_SESSION['ug_master_flash']=$flash;
 header('Location: admin.php',true,303);
 exit;
}

$stats=[
 'total'=>count($restaurants),
 'ativos'=>count(array_filter($restaurants,fn($r)=>($r['status']??'ATIVO')==='ATIVO')),
 'licencas'=>count($licenses),'usuarios'=>count($users)
];
?>
<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>UniGestor — Painel Central</title>
<style>
body{font-family:Arial;margin:0;background:#f4f6f8;color:#18212b}
header{background:linear-gradient(135deg,#062f68,#0b4f9c);color:#fff;padding:18px 24px;display:flex;justify-content:space-between;align-items:center}
main{max-width:1250px;margin:24px auto;padding:0 16px}.card{background:#fff;border-radius:12px;padding:18px;margin-bottom:18px;box-shadow:0 2px 12px #0001}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px}.metric{font-size:28px;font-weight:900;margin-top:5px}.stat{border:1px solid #e4e8ed}
.formgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px}
input,select,button{padding:10px;border:1px solid #ccd3da;border-radius:7px;box-sizing:border-box}button{cursor:pointer}
.primary{background:#0b4f9c;color:white;border:0}.ok{color:#087b38;font-weight:700}.bad{color:#b42318;font-weight:700}.warn{color:#9a6700;font-weight:700}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{padding:10px;border-bottom:1px solid #e7eaee;text-align:left;vertical-align:top}
.actions form{display:inline-flex;gap:5px;margin:2px}.key{font-family:monospace;font-weight:700}.flash{background:#e7f6ec;padding:12px;border-radius:8px}.small{color:#667;font-size:13px}
.module-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:8px;margin-top:10px}
.module-grid label{border:1px solid #dfe5eb;border-radius:8px;padding:9px;background:#f9fbfd;display:flex;gap:8px}
.tag{display:inline-block;background:#eaf2fb;color:#0b4f9c;border-radius:20px;padding:3px 8px;margin:2px;font-size:12px}
.section-blue{border-left:5px solid #0b4f9c}
@media(max-width:800px){table{display:block;overflow:auto}}
</style>
<header><strong>🔷 UNIGESTOR — PAINEL CENTRAL</strong><a class="logout" href="setup.php?logout=1" style="color:#fff">Sair</a></header>
<main>
<?php if($flash):?><div class="card flash"><b><?=h($flash)?></b></div><?php endif?>

<div class="grid">
<div class="card stat"><span>Empresas</span><div class="metric"><?=$stats['total']?></div></div>
<div class="card stat"><span>Ativas</span><div class="metric"><?=$stats['ativos']?></div></div>
<div class="card stat"><span>Licenças</span><div class="metric"><?=$stats['licencas']?></div></div>
<div class="card stat"><span>Usuários</span><div class="metric"><?=$stats['usuarios']?></div></div>
</div>

<div class="card section-blue">
<h2>🏢 Nova empresa + licença</h2>
<form method="post" class="formgrid"><?=ug_master_csrf_field()?>
<input type="hidden" name="act" value="create">
<input name="establishment" placeholder="Nome da empresa" required>
<input name="client" placeholder="Responsável" required>
<input name="document" placeholder="CNPJ/CPF">
<input name="phone" placeholder="Telefone">
<input name="address" placeholder="Endereço">
<input name="login" placeholder="Login do administrador" required>
<select name="segment" id="segmentSelect" onchange="aplicarModelo()">
<?php foreach($segments as $k=>$v):?><option value="<?=h($k)?>"><?=h($v)?></option><?php endforeach?>
</select>
<select name="days"><option value="30">30 dias</option><option value="60">60 dias</option><option value="90">90 dias</option><option value="365">1 ano</option></select>
<input name="notes" placeholder="Observação">
<label>Acessos simultâneos contratados <input type="number" name="access_limit" min="1" max="500" value="1" required></label>
<label>Valor do pacote (R$) <input type="number" name="package_price" min="0" step="0.01" value="0.00" required></label>
<div style="grid-column:1/-1"><b>Módulos liberados para esta empresa</b><div class="module-grid">
<?php foreach($moduleOptions as $m):?><label><input type="checkbox" name="modules[]" value="<?=h($m)?>" class="empresa-mod" checked> <?=h($m)?></label><?php endforeach?>
</div></div>
<button class="primary" style="grid-column:1/-1">CRIAR EMPRESA + LICENÇA + ADMINISTRADOR</button>
</form>
</div>

<div class="card section-blue">
<h2>👤 Novo usuário e permissões</h2>
<p class="small">Selecione a empresa, crie o usuário e marque exatamente o que ele poderá acessar.</p>
<form method="post" class="formgrid"><?=ug_master_csrf_field()?>
<input type="hidden" name="act" value="create_user">
<select name="restaurant_id" required>
<option value="">Selecione a empresa</option>
<?php foreach($restaurants as $r):?><option value="<?=h($r['id'])?>"><?=h($r['name'])?> — <?=h($segments[$r['segment']??'']??($r['segment_name']??'Comércio geral'))?></option><?php endforeach?>
</select>
<input name="user_name" placeholder="Nome do usuário" required>
<input name="user_login" placeholder="Login" required>
<input name="user_password" type="password" placeholder="Senha" required>
<select name="user_role"><option>ADMINISTRADOR</option><option>GERENTE</option><option>CAIXA</option><option>VENDEDOR</option><option>GARÇOM</option><option>ESTOQUE</option><option>FINANCEIRO</option></select>
<div style="grid-column:1/-1"><b>Permissões</b><div class="module-grid">
<?php foreach($moduleOptions as $m):?><label><input type="checkbox" name="permissions[]" value="<?=h($m)?>"> <?=h($m)?></label><?php endforeach?>
</div></div>
<button class="primary" style="grid-column:1/-1">CRIAR USUÁRIO</button>
</form>
</div>

<div class="card section-blue">
<h2>🔐 Usuários cadastrados</h2>
<p class="small">Use <b>EDITAR</b> para alterar nome, perfil, senha, status e permissões sem excluir o usuário.</p>
<table><thead><tr><th>Usuário</th><th>Empresa</th><th>Perfil</th><th>Status</th><th>Permissões</th><th>Ações</th></tr></thead><tbody>
<?php foreach($users as $u):
 $rr=array_values(array_filter($restaurants,fn($r)=>($r['id']??'')===($u['restaurant_id']??''))); $rr=$rr[0]??[];
 $perms=$u['permissions']??$u['permissoes']??[];
?>
<tr>
<td><b><?=h($u['name']??'')?></b><br><span class="small"><?=h($u['login']??'')?></span></td>
<td><?=h($rr['name']??'-')?></td><td><?=h($u['role']??'USUARIO')?></td>
<td><?=!empty($u['active'])?'<span class="ok">ATIVO</span>':'<span class="bad">INATIVO</span>'?></td>
<td><?php foreach($perms as $pm):?><span class="tag"><?=h($pm)?></span><?php endforeach?></td>
<td><details><summary style="cursor:pointer;background:#0b4f9c;color:#fff;padding:8px 12px;border-radius:7px;display:inline-block">✏️ EDITAR</summary>
<form method="post" style="margin-top:10px;padding:12px;border:1px solid #dfe5eb;border-radius:9px;background:#f8fbff"><?=ug_master_csrf_field()?>
<input type="hidden" name="act" value="update_user"><input type="hidden" name="user_id" value="<?=h($u['id']??'')?>">
<div class="formgrid">
<input name="user_name" value="<?=h($u['name']??'')?>" placeholder="Nome">
<select name="user_role"><?php foreach(['ADMINISTRADOR','GERENTE','CAIXA','VENDEDOR','GARÇOM','ESTOQUE','FINANCEIRO'] as $role):?><option <?=$role===($u['role']??'')?'selected':''?>><?=$role?></option><?php endforeach?></select>
<input name="user_password" type="password" placeholder="Nova senha (vazio = manter)">
</div>
<div style="margin-top:10px"><b>Permissões</b><div class="module-grid">
<?php foreach($moduleOptions as $mod):?><label><input type="checkbox" name="permissions[]" value="<?=h($mod)?>" <?=in_array($mod,$perms,true)?'checked':''?>> <?=h($mod)?></label><?php endforeach?>
</div></div>
<label style="display:block;margin-top:10px"><input type="checkbox" name="active" <?=!empty($u['active'])?'checked':''?>> Usuário ativo</label>
<button class="primary" style="margin-top:12px">💾 SALVAR ALTERAÇÕES</button>
</form></details></td>
</tr>
<?php endforeach?>
</tbody></table>
</div>
<div class="card section-blue">
<h2 id="editar-pacotes-empresa">💼 Pacotes, acessos e módulos por empresa</h2>
<p class="small">Configure o segmento, os módulos visíveis e o número de acessos contratados. As alterações do pacote passam a valer no próximo login do Gestor.</p>
<?php foreach($restaurants as $r): ?>
<details id="editar-empresa-<?=h($r['id']??'')?>" style="border:1px solid #dfe5eb;border-radius:8px;padding:12px;margin:10px 0;background:#fff">
<summary style="cursor:pointer;font-weight:bold"><?=h($r['name']??'Empresa')?> — <?=ug_limit($r['access_limit']??1)?> acesso(s) — R$ <?=number_format((float)($r['package_price']??0),2,',','.')?></summary>
<form method="post" class="formgrid" style="margin-top:12px"><?=ug_master_csrf_field()?>
<input type="hidden" name="act" value="update_package"><input type="hidden" name="restaurant_id" value="<?=h($r['id']??'')?>">
<label>Segmento<select name="segment"><?php foreach($segments as $key=>$label):?><option value="<?=h($key)?>" <?=($r['segment']??'COMERCIO')===$key?'selected':''?>><?=h($label)?></option><?php endforeach?></select></label>
<label>Acessos simultâneos contratados<input type="number" name="access_limit" min="1" max="500" value="<?=ug_limit($r['access_limit']??1)?>" required></label>
<label>Valor do pacote (R$)<input type="number" name="package_price" min="0" step="0.01" value="<?=number_format((float)($r['package_price']??0),2,'.','')?>" required></label>
<div style="grid-column:1/-1"><b>Módulos autorizados</b><div class="module-grid">
<?php foreach($moduleOptions as $m):?><label><input type="checkbox" name="modules[]" value="<?=h($m)?>" <?=in_array($m,$r['modules']??[],true)?'checked':''?>> <?=h($m)?></label><?php endforeach?></div></div>
<button class="primary" style="grid-column:1/-1">💾 SALVAR PACOTE E MÓDULOS</button>
</form></details>
<?php endforeach?>
</div>
<div class="card">
<h2>🏪 Empresas, segmentos e licenças</h2>
<table><thead><tr><th>Empresa</th><th>Segmento</th><th>Responsável</th><th>Chave</th><th>Status</th><th>Vencimento</th><th>Ações</th></tr></thead><tbody>
<?php foreach(array_reverse($licenses) as $l):
$st=status_license($l); $rid=$l['restaurant_id']??'';
$r=array_values(array_filter($restaurants,fn($x)=>($x['id']??'')===$rid)); $r=$r[0]??[];
?>
<tr>
<td><b><?=h($l['establishment']??'')?></b><br><span class="small"><?=h($r['phone']??'')?></span></td>
<td><?=h($segments[$r['segment']??'']??($r['segment_name']??'Comércio geral'))?><br>
<?php foreach(($r['modules']??[]) as $m):?><span class="tag"><?=h($m)?></span><?php endforeach?></td>
<td><?=h($l['client']??'')?></td><td class="key"><?=h($l['key']??'')?></td>
<td class="<?=$st==='ATIVA'?'ok':($st==='BLOQUEADA'?'bad':'warn')?>"><?=$st?><br><?php if($st==='ATIVA'):?><?=days_left($l)?> dias<?php endif?></td>
<td><?=h($l['expires_at']??'')?></td>
<td class="actions"><a href="#editar-pacotes-empresa" onclick="setTimeout(function(){var el=document.getElementById('editar-empresa-<?=h($rid)?>');if(el){el.open=true;el.scrollIntoView({behavior:'smooth',block:'center'});}},50)" style="display:inline-block;padding:8px 10px;background:#1656a2;color:#fff;border-radius:6px;text-decoration:none;font-weight:700">✏️ Editar empresa</a>
<form method="post"><?=ug_master_csrf_field()?><input type="hidden" name="act" value="extend"><input type="hidden" name="key" value="<?=h($l['key'])?>"><select name="days"><option>30</option><option>60</option><option>90</option><option>365</option></select><button>Renovar</button></form>
<form method="post"><?=ug_master_csrf_field()?><input type="hidden" name="act" value="toggle"><input type="hidden" name="key" value="<?=h($l['key'])?>"><button><?=$l['blocked']?'Desbloquear':'Bloquear'?></button></form>
</td></tr>
<?php endforeach?></tbody></table>
</div>

<div class="card"><h2>🔄 Atualização central</h2><p class="small">O Painel Central cria backup antes da atualização e preserva a pasta de licença.</p><input id="pacoteAtualizacao" type="file" accept=".zip,application/zip"><button class="primary" type="button" onclick="atualizarCentral()">ATUALIZAR UNIGESTOR</button> <a href="backup.php" style="display:inline-block;margin-left:8px">BAIXAR BACKUP COMPLETO</a><p id="statusAtualizacao" class="small"></p></div>

</main>
<script>
const MODELOS={
 COMERCIO:["PDV/Vendas","Caixa","Clientes","Produtos","Estoque","Financeiro","Relatórios"],
 RESTAURANTE:["PDV/Vendas","Mesas","Comandas","Caixa","Cozinha/KDS","Produtos","Grupos","Clientes","Financeiro","Garçom Mobile","Delivery","Relatórios","Pedidos","Comissões"],
 MERCANTIL:["PDV/Vendas","Caixa","Produtos","Estoque","Clientes","Compras","Financeiro","Relatórios"],
 ROUPAS:["PDV/Vendas","Caixa","Produtos","Estoque","Clientes","Financeiro","Relatórios","Comissões"],
 CALCADOS:["PDV/Vendas","Caixa","Produtos","Estoque","Clientes","Financeiro","Relatórios","Comissões"],
 ELETRONICOS:["PDV/Vendas","Caixa","Produtos","Estoque","Clientes","Financeiro","Relatórios"],
 SERVICOS:["PDV/Vendas","Caixa","Clientes","Financeiro","Relatórios"]
};
function aplicarModelo(){
 const s=document.getElementById('segmentSelect')?.value, allowed=MODELOS[s]||[];
 document.querySelectorAll('.empresa-mod').forEach(x=>x.checked=allowed.includes(x.value));
}
async function atualizarCentral(){
 const f=document.getElementById('pacoteAtualizacao').files[0],s=document.getElementById('statusAtualizacao');
 if(!f){alert('Selecione o ZIP oficial da nova versão.');return}
 if(!confirm('Será criado um backup e a nova versão será instalada. Continuar?'))return;
 s.textContent='Enviando e atualizando...';
 const fd=new FormData();fd.append('pacote',f);
 try{const tokenResponse=await fetch('ug_master_csrf.php',{credentials:'same-origin',cache:'no-store'});
    const tokenData=await tokenResponse.json();
    if(!tokenResponse.ok||!tokenData.ok||!tokenData.csrf)throw new Error('Autentique-se no Painel Master para atualizar.');
    fd.append('ug_csrf',tokenData.csrf);
    const r=await fetch('../atualizar.php',{method:'POST',body:fd,credentials:'same-origin'});const d=await r.json();if(!r.ok||!d.ok)throw new Error(d.message||'Falha na atualização.');s.textContent='Atualização concluída. Arquivos instalados: '+(d.arquivos_instalados??'-')+' | Backup: '+(d.backup||'-')}catch(e){s.textContent='Erro: '+e.message}
}
</script>
