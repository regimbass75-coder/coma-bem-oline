<?php require __DIR__.'/lib.php'; start_admin();
if(isset($_GET['logout'])){ session_destroy(); header('Location: setup.php'); exit; }
$msg='';
if(!configured() && $_SERVER['REQUEST_METHOD']==='POST'){
 $setupToken=(string)getenv('UG_SETUP_TOKEN');
 if(strlen($setupToken)<32){http_response_code(503);$msg='O servidor ainda não recebeu um UG_SETUP_TOKEN válido (mínimo 32 caracteres). Verifique a publicação das variáveis no Render.';} elseif(!hash_equals($setupToken,(string)($_POST['setup_token']??''))){http_response_code(403);$msg='O código digitado não coincide com o código configurado no Render. Confira espaços extras ao copiar, sem enviar o código a ninguém.';}
 else {
 $p=(string)($_POST['password']??''); $p2=(string)($_POST['password2']??'');
 if(strlen($p)<8) $msg='Use uma senha com pelo menos 8 caracteres.'; elseif($p!==$p2) $msg='As senhas não conferem.'; else { write_json(ADMIN_FILE,['password_hash'=>password_hash($p,PASSWORD_DEFAULT),'created_at'=>date('c')]); $_SESSION['master_ok']=true; header('Location: admin.php'); exit; }
}
}elseif(configured() && $_SERVER['REQUEST_METHOD']==='POST'){
 $a=read_json(ADMIN_FILE); if(password_verify((string)($_POST['password']??''),$a['password_hash']??'')){ $_SESSION['master_ok']=true; header('Location: admin.php'); exit; } else $msg='Senha incorreta.';
}
?>
<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Coma Bem Master</title><style>body{font-family:Arial;background:#f3f5f7;margin:0}.box{max-width:430px;margin:8vh auto;background:#fff;padding:28px;border-radius:14px;box-shadow:0 8px 30px #0002}h1{margin-top:0}input,button{box-sizing:border-box;width:100%;padding:12px;margin:7px 0;border:1px solid #ccd3da;border-radius:8px}button{background:#173b63;color:#fff;font-weight:700;cursor:pointer}.err{color:#a00}.small{color:#667;font-size:13px}</style><div class="box"><h1>🍽 Coma Bem Master</h1><p><?=configured()?'Entre com a senha do administrador master.':'Primeiro acesso: crie a senha exclusiva do Painel Master.'?></p><?php if($msg):?><p class="err"><?=h($msg)?></p><?php endif?><form method="post"><?php if(!configured()):?><input type="password" name="setup_token" placeholder="Código de instalação (UG_SETUP_TOKEN)" required><?php endif?><input type="password" name="password" placeholder="Senha Master" required><?php if(!configured()):?><input type="password" name="password2" placeholder="Repita a senha" required><?php endif?><button><?=configured()?'Entrar':'Criar Painel Master'?></button></form><p class="small">A senha não é gravada em texto puro.</p></div></html>
