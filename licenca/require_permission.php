<?php
require_once __DIR__ . '/lib.php';
require_once __DIR__ . '/ug_permissions.php';
require_once __DIR__ . '/ug_sessions.php';
function ug_require_module(string|array $module): void {
    start_app();
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    $deny = static function (string $message, int $code=403): void {
        http_response_code($code);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok'=>false,'erro'=>$message],JSON_UNESCAPED_UNICODE);
        exit;
    };
    $uid=(string)($_SESSION['user_id']??'');
    $rid=(string)($_SESSION['restaurant_id']??'');
    if ($uid==='' || $rid==='') $deny('Sessão necessária.',401);
    try{$sessionOk=ug_session_valid();}catch(Throwable $e){$sessionOk=false;}
    if(!$sessionOk)$deny('Sessão expirada ou revogada.',401);
    $user=null;
    foreach (read_json(USERS_FILE,[]) as $item) {
        if (is_array($item) && (string)($item['id']??'')===$uid &&
            (string)($item['restaurant_id']??'')===$rid) { $user=$item; break; }
    }
    if (!$user || ($user['active']??true)!==true) $deny('Usuário inativo ou inexistente.');
    if (!ug_restaurant_active($rid)) $deny('Restaurante não autorizado.');
    $license=license_for_restaurant($rid);
    if (!$license || status_license($license)!=='ATIVA') $deny('Licença inativa.');
    $requested=is_array($module)?$module:[$module];
    if (!$requested) $deny('Módulo inválido.');
    foreach ($requested as $name) {
        if (!is_string($name) || $name==='' || trim($name)!==$name) $deny('Módulo inválido.');
    }
    $permitted=false;
    foreach ($requested as $name) if (ug_can_module($rid,$user,$name)) { $permitted=true; break; }
    if (!$permitted) $deny('Módulo não autorizado.');
    $origin=$_SERVER['HTTP_ORIGIN']??'';
    if ($origin!=='') {
        $scheme=(!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS']!=='off')?'https':'http';
        $host=$_SERVER['HTTP_HOST']??'';
        if ($host==='' || !hash_equals(strtolower($scheme.'://'.$host),strtolower(rtrim($origin,'/')))) $deny('Origem não autorizada.');
    }
}
