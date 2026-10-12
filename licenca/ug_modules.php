<?php
// Catálogo idêntico ao Painel Master; nenhuma autorização implícita.
function ug_module_catalog(): array {
 return ['PDV/Vendas','Mesas','Comandas','Caixa','Cozinha/KDS','Produtos','Grupos','Clientes','Financeiro','Fiscal','Garçom Mobile','Delivery','Relatórios','Usuários/Permissões','Configurações','Compras','Estoque','Comissões','Pedidos','Venda Externa'];
}
function ug_valid_modules($mods): array {
 if(!is_array($mods)) return [];
 $catalog=ug_module_catalog(); $result=[];
 foreach($mods as $m)if(is_string($m)&&in_array($m,$catalog,true)&&!in_array($m,$result,true))$result[]=$m;
 return $result;
}
function ug_restaurant_by_id($rid): ?array {
 foreach(read_json(RESTAURANTS_FILE,[]) as $r)
  if(is_array($r)&&(string)($r['id']??'')===(string)$rid)return $r;
 return null;
}
function ug_module_state($rid,$user): array {
 $r=ug_restaurant_record($rid);
 $configured=$r!==null && array_key_exists('modules',$r) && is_array($r['modules']);
 $restaurant=$configured ? ug_valid_modules(ug_company_modules($rid)) : [];
 $permissions=ug_valid_modules(ug_user_permissions($user));
 $effective=ug_valid_modules(ug_effective_permissions($user));
 return ['configured'=>$configured,'restaurant_modules'=>$restaurant,
 'user_permissions'=>$permissions,'effective_modules'=>$effective];
}
