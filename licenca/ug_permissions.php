<?php
require_once __DIR__.'/ug_modules.php';
// UniGestor V8: permissões efetivas = módulos contratados ∩ permissões individuais.
// Política segura: ausência de configuração não concede acesso.
function ug_restaurant_record($rid) {
    foreach (read_json(RESTAURANTS_FILE, []) as $r)
        if (is_array($r) && (string)($r['id']??'') === (string)$rid) return $r;
    return null;
}
function ug_restaurant_active($rid) {
    $r=ug_restaurant_record($rid);
    return $r !== null && strtoupper((string)($r['status']??'')) === 'ATIVO';
}
function ug_normalize_modules($values) {
    if (!is_array($values) || !array_is_list($values)) return [];
    $out=[];
    foreach ($values as $v) {
        if (!is_string($v) || trim($v)==='' || $v!==trim($v)) continue;
        if (!in_array($v,$out,true)) $out[]=$v;
    }
    return $out;
}
function ug_company_modules($rid) {
    $r=ug_restaurant_record($rid);
    return $r ? ug_normalize_modules($r['modules']??null) : [];
}
function ug_user_permissions($u) {
    return is_array($u) ? ug_normalize_modules($u['permissions']??null) : [];
}
function ug_effective_permissions($user) {
    if (!is_array($user) || ($user['active']??true)!==true) return [];
    $rid=(string)($user['restaurant_id']??'');
    if ($rid==='' || !ug_restaurant_active($rid)) return [];
    return ug_valid_modules(array_values(array_intersect(ug_company_modules($rid),ug_user_permissions($user))));
}
function ug_can_module($rid,$user,$module) {
    if (!is_string($module) || $module==='' || !is_array($user)) return false;
    if ((string)($user['restaurant_id']??'') !== (string)$rid) return false;
    return in_array($module,ug_effective_permissions($user),true);
}
function ug_require_user_module($module) {
    start_app();
    require_once __DIR__.'/ug_sessions.php';
    if (empty($_SESSION['user_id']) || empty($_SESSION['restaurant_id'])) {
        http_response_code(401); exit('Sessão inválida.');
    }
    try{$sessionOk=ug_session_valid();}catch(Throwable $e){$sessionOk=false;}
    if(!$sessionOk){http_response_code(401);exit('Sessão expirada ou revogada.');}
    $user=null;
    foreach (read_json(USERS_FILE,[]) as $candidate) {
        if (is_array($candidate) &&
            (string)($candidate['id']??'') === (string)$_SESSION['user_id'] &&
            (string)($candidate['restaurant_id']??'') === (string)$_SESSION['restaurant_id']) {
            $user=$candidate; break;
        }
    }
    if (!$user || !ug_can_module($_SESSION['restaurant_id'],$user,$module)) {
        http_response_code(403); exit('Acesso negado.');
    }
    $lic=license_for_restaurant($_SESSION['restaurant_id']);
    if (!$lic || status_license($lic)!=='ATIVA') {
        http_response_code(403); exit('Licença inválida.');
    }
    return $user;
}

function ug_permission_decision($restaurantId, $user, $module) {
    if (!is_string($module) || $module==='') return ['allowed'=>false,'reason'=>'invalid_module'];
    if (!is_array($user)) return ['allowed'=>false,'reason'=>'missing_user'];
    if (($user['active']??true)!==true) return ['allowed'=>false,'reason'=>'inactive_user'];
    if ((string)($user['restaurant_id']??'')!==(string)$restaurantId) return ['allowed'=>false,'reason'=>'restaurant_mismatch'];
    if (!ug_restaurant_active($restaurantId)) return ['allowed'=>false,'reason'=>'inactive_restaurant'];
    if (!in_array($module,ug_company_modules($restaurantId),true)) return ['allowed'=>false,'reason'=>'module_not_licensed'];
    if (!in_array($module,ug_user_permissions($user),true)) return ['allowed'=>false,'reason'=>'user_not_permitted'];
    return ['allowed'=>true,'reason'=>'allowed'];
}
