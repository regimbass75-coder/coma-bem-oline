<?php
require __DIR__.'/lib.php';
require_admin();
if(!isset($_SESSION['ug_master_csrf']) || !is_string($_SESSION['ug_master_csrf']) || !preg_match('/^[a-f0-9]{64}$/D',$_SESSION['ug_master_csrf'])) {
    $_SESSION['ug_master_csrf']=bin2hex(random_bytes(32));
}

$restaurants=read_json(RESTAURANTS_FILE,[]);
$finance=read_json(FINANCE_FILE,[]);
$flash='';

function money_br($v){ return 'R$ '.number_format((float)$v,2,',','.'); }
function is_overdue($item){
    return ($item['type']??'')==='receber' && ($item['status']??'aberto')!=='pago' && !empty($item['due_date']) && $item['due_date'] < date('Y-m-d');
}
function restaurant_name($restaurants,$rid){ foreach($restaurants as $r) if(($r['id']??'')===$rid) return $r['name']??$rid; return $rid ?: 'Sem restaurante'; }

if($_SERVER['REQUEST_METHOD']==='POST'){
    $provided=$_POST['ug_csrf']??'';
    if(!is_string($provided) || !hash_equals($_SESSION['ug_master_csrf'],$provided)){
        http_response_code(403);
        header('Content-Type: text/plain; charset=utf-8');
        exit('Operação recusada: token de segurança inválido.');
    }

    $act=$_POST['act']??'';
    if($act==='add'){
        $rid=trim($_POST['restaurant_id']??'');
        $type=$_POST['type']??'receber';
        $amount=(float)str_replace(',','.',preg_replace('/[^0-9,.-]/','',$_POST['amount']??'0'));
        $client=trim($_POST['client']??'');
        $description=trim($_POST['description']??'');
        $due=trim($_POST['due_date']??'');
        if(!in_array($type,['receber','pagar'],true)) $type='receber';
        if($rid==='' || !in_array($rid,array_map(fn($r)=>(string)($r['id']??''),$restaurants),true) || $amount<=0 || !preg_match('/^\d{4}-\d{2}-\d{2}$/D',$due) || !checkdate((int)substr($due,5,2),(int)substr($due,8,2),(int)substr($due,0,4)) || !$description){ $flash='Preencha descrição, valor e vencimento.'; }
        elseif($type==='receber' && !$client){ $flash='Informe o cliente para uma conta a receber.'; }
        else {
            $finance[]=[
                'id'=>'FIN-'.strtoupper(substr(bin2hex(random_bytes(6)),0,12)),
                'restaurant_id'=>$rid,
                'type'=>$type,
                'client'=>$client,
                'description'=>$description,
                'amount'=>round($amount,2),
                'due_date'=>$due,
                'status'=>'aberto',
                'created_at'=>date('c'),
                'paid_at'=>null
            ];
            write_json(FINANCE_FILE,$finance);
            $flash='Lançamento financeiro criado com sucesso.';
        }
    } elseif($act==='pay'){
        $id=$_POST['id']??'';
        foreach($finance as &$f) if(($f['id']??'')===$id){ $f['status']='pago'; $f['paid_at']=date('c'); }
        unset($f); write_json(FINANCE_FILE,$finance); $flash='Lançamento marcado como pago.';
    } elseif($act==='reopen'){
        $id=$_POST['id']??'';
        foreach($finance as &$f) if(($f['id']??'')===$id){ $f['status']='aberto'; $f['paid_at']=null; }
        unset($f); write_json(FINANCE_FILE,$finance); $flash='Lançamento reaberto.';
    } elseif($act==='delete'){
        $id=$_POST['id']??'';
        $finance=array_values(array_filter($finance,fn($f)=>($f['id']??'')!==$id));
        write_json(FINANCE_FILE,$finance); $flash='Lançamento excluído.';
    }
}

$filterRid=trim($_GET['restaurant_id']??'');
$filterType=$_GET['type']??'';
$filterStatus=$_GET['status']??'';
$dateFrom=trim($_GET['date_from']??'');
$dateTo=trim($_GET['date_to']??'');
$rows=array_reverse($finance);
if($filterRid!=='') $rows=array_values(array_filter($rows,fn($f)=>($f['restaurant_id']??'')===$filterRid));
if(in_array($filterType,['receber','pagar','vencidos'],true)){
    if($filterType==='receber') $rows=array_values(array_filter($rows,fn($f)=>($f['type']??'')==='receber'));
    if($filterType==='pagar') $rows=array_values(array_filter($rows,fn($f)=>($f['type']??'')==='pagar'));
    if($filterType==='vencidos') $rows=array_values(array_filter($rows,'is_overdue'));
}
if(in_array($filterStatus,['aberto','pago'],true)) $rows=array_values(array_filter($rows,fn($f)=>($f['status']??'')===$filterStatus));
if($dateFrom!=='') $rows=array_values(array_filter($rows,fn($f)=>($f['due_date']??'')>=$dateFrom));
if($dateTo!=='') $rows=array_values(array_filter($rows,fn($f)=>($f['due_date']??'')<=$dateTo));

$visibleReceber=array_sum(array_map(fn($f)=>($f['type']??'')==='receber' && ($f['status']??'')!=='pago'?(float)$f['amount']:0,$rows));
$visiblePagar=array_sum(array_map(fn($f)=>($f['type']??'')==='pagar' && ($f['status']??'')!=='pago'?(float)$f['amount']:0,$rows));
$visibleVencido=array_sum(array_map(fn($f)=>is_overdue($f)?(float)$f['amount']:0,$rows));

$totalReceber=array_sum(array_map(fn($f)=>($f['type']??'')==='receber' && ($f['status']??'')!=='pago'?(float)$f['amount']:0,$finance));
$totalPagar=array_sum(array_map(fn($f)=>($f['type']??'')==='pagar' && ($f['status']??'')!=='pago'?(float)$f['amount']:0,$finance));
$totalVencido=array_sum(array_map(fn($f)=>is_overdue($f)?(float)$f['amount']:0,$finance));
$qtdVencidos=count(array_filter($finance,'is_overdue'));
$totalPago=array_sum(array_map(fn($f)=>($f['status']??'')==='pago'?(float)$f['amount']:0,$finance));
$saldoAberto=$totalReceber-$totalPagar;
?>
<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Financeiro - Coma Bem Master</title>
<style>body{font-family:Arial;margin:0;background:#f4f6f8;color:#18212b}header{background:#173b63;color:#fff;padding:18px 24px;display:flex;justify-content:space-between;align-items:center}header a{color:#fff}main{max-width:1250px;margin:24px auto;padding:0 16px}.card{background:#fff;border-radius:12px;padding:18px;margin-bottom:18px;box-shadow:0 2px 12px #0001}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}.metric{font-size:25px;font-weight:900;margin-top:5px}.stat{border:1px solid #e4e8ed}.formgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px}input,select,button{padding:10px;border:1px solid #ccd3da;border-radius:7px;box-sizing:border-box}button{cursor:pointer}.primary{background:#173b63;color:white;border:0}.green{background:#087b38;color:#fff;border:0}.red{background:#b42318;color:#fff;border:0}.warn{color:#9a6700;font-weight:700}.bad{color:#b42318;font-weight:700}.ok{color:#087b38;font-weight:700}table{width:100%;border-collapse:collapse;font-size:14px}th,td{padding:10px;border-bottom:1px solid #e7eaee;text-align:left;vertical-align:top}.actions form{display:inline-flex;margin:2px}.flash{background:#e7f6ec;padding:12px;border-radius:8px}.nav{margin-bottom:15px}.nav a{display:inline-block;margin-right:8px;padding:9px 12px;border-radius:7px;background:#fff;border:1px solid #ccd3da;color:#173b63;text-decoration:none}.small{color:#667;font-size:13px}@media(max-width:800px){table{display:block;overflow:auto}}</style>
<header><strong>💰 COMA BEM — FINANCEIRO MASTER</strong><a href="admin.php">← Voltar ao Painel Master</a></header><main>
<div class="nav"><a href="admin.php">🏪 Restaurantes</a><a href="financeiro.php?type=receber">📥 Contas a receber</a><a href="financeiro.php?type=pagar">📤 Contas a pagar</a><a href="financeiro.php?type=vencidos">⚠️ Clientes vencidos</a></div>
<?php if($flash):?><div class="card flash"><b><?=h($flash)?></b></div><?php endif?>
<div class="grid"><div class="card stat"><span>A receber em aberto</span><div class="metric"><?=money_br($totalReceber)?></div></div><div class="card stat"><span>A pagar em aberto</span><div class="metric"><?=money_br($totalPagar)?></div></div><div class="card stat"><span>Saldo em aberto</span><div class="metric"><?=money_br($saldoAberto)?></div></div><div class="card stat"><span>Total vencido</span><div class="metric <?=$totalVencido?'bad':''?>"><?=money_br($totalVencido)?></div><span><?=$qtdVencidos?> lançamento(s) vencido(s)</span></div></div>
<div class="card"><h2>Novo lançamento</h2><form method="post"><input type="hidden" name="ug_csrf" value="<?=h($_SESSION['ug_master_csrf'])?>" class="formgrid"><input type="hidden" name="act" value="add"><select name="restaurant_id" required><option value="">Selecione o restaurante</option><?php foreach($restaurants as $r):?><option value="<?=h($r['id'])?>" <?=($filterRid===($r['id']??''))?'selected':''?>><?=h($r['name']??$r['id'])?></option><?php endforeach?></select><select name="type"><option value="receber">Conta a receber</option><option value="pagar">Conta a pagar</option></select><input name="client" placeholder="Cliente / fornecedor"><input name="description" placeholder="Descrição" required><input name="amount" placeholder="Valor (ex.: 150,00)" required><input type="date" name="due_date" required><button class="primary">LANÇAR NO FINANCEIRO</button></form><p class="small">Contas a receber vencidas aparecem automaticamente em “Clientes vencidos”.</p></div>
<div class="card"><h2>Filtros</h2><form method="get" class="formgrid"><select name="restaurant_id"><option value="">Todos os restaurantes</option><?php foreach($restaurants as $r):?><option value="<?=h($r['id'])?>" <?=($filterRid===($r['id']??''))?'selected':''?> ><?=h($r['name']??$r['id'])?></option><?php endforeach?></select><select name="type"><option value="">Todos os tipos</option><option value="receber" <?= $filterType==='receber'?'selected':''?>>A receber</option><option value="pagar" <?= $filterType==='pagar'?'selected':''?>>A pagar</option><option value="vencidos" <?= $filterType==='vencidos'?'selected':''?>>Vencidos</option></select><select name="status"><option value="">Todos os status</option><option value="aberto" <?= $filterStatus==='aberto'?'selected':''?>>Em aberto</option><option value="pago" <?= $filterStatus==='pago'?'selected':''?>>Pagos</option></select><input type="date" name="date_from" value="<?=h($dateFrom)?>"><input type="date" name="date_to" value="<?=h($dateTo)?>"><button class="primary">FILTRAR</button><a href="financeiro.php" style="padding:10px 12px">LIMPAR</a></form><p class="small">No resultado filtrado: a receber <?=money_br($visibleReceber)?> · a pagar <?=money_br($visiblePagar)?> · vencido <?=money_br($visibleVencido)?></p></div><div class="card"><h2>Movimentações financeiras</h2><table><thead><tr><th>Restaurante</th><th>Tipo</th><th>Cliente/Fornecedor</th><th>Descrição</th><th>Vencimento</th><th>Valor</th><th>Status</th><th>Ações</th></tr></thead><tbody><?php if(!$rows):?><tr><td colspan="8">Nenhum lançamento encontrado.</td></tr><?php else: foreach($rows as $f): $over=is_overdue($f);?><tr><td><?=h(restaurant_name($restaurants,$f['restaurant_id']??''))?></td><td><?=($f['type']??'')==='receber'?'A RECEBER':'A PAGAR'?></td><td><?=h($f['client']??'')?></td><td><?=h($f['description']??'')?></td><td class="<?=$over?'bad':''?>"><?=h($f['due_date']??'')?></td><td><?=money_br($f['amount']??0)?></td><td><?php if(($f['status']??'')==='pago'):?><span class="ok">PAGO</span><?php elseif($over):?><span class="bad">VENCIDO</span><?php else:?><span class="warn">ABERTO</span><?php endif?></td><td class="actions"><?php if(($f['status']??'')==='pago'):?><form method="post"><input type="hidden" name="ug_csrf" value="<?=h($_SESSION['ug_master_csrf'])?>"><input type="hidden" name="act" value="reopen"><input type="hidden" name="id" value="<?=h($f['id'])?>"><button>Reabrir</button></form><?php else:?><form method="post"><input type="hidden" name="ug_csrf" value="<?=h($_SESSION['ug_master_csrf'])?>"><input type="hidden" name="act" value="pay"><input type="hidden" name="id" value="<?=h($f['id'])?>"><button class="green">Marcar pago</button></form><?php endif?><form method="post"><input type="hidden" name="ug_csrf" value="<?=h($_SESSION['ug_master_csrf'])?>" onsubmit="return confirm('Excluir este lançamento?')"><input type="hidden" name="act" value="delete"><input type="hidden" name="id" value="<?=h($f['id'])?>"><button class="red">Excluir</button></form></td></tr><?php endforeach; endif?></tbody></table></div>
</main></html>
