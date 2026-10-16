<?php
declare(strict_types=1);
require __DIR__.'/lib.php';
require_admin();
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') { http_response_code(405); exit('Método inválido.'); }
if (!class_exists('ZipArchive')) { http_response_code(503); exit('Extensão ZipArchive indisponível.'); }
$root=realpath(dirname(__DIR__));
if ($root===false) { http_response_code(500); exit('Raiz inválida.'); }
// Backup temporário fora da raiz pública, nunca em /data/backups.
$private=rtrim(DATA_DIR,'/').'/.ug_private_backups_'.substr(hash('sha256',$root),0,12);
if ((!is_dir($private) && !@mkdir($private,0700,true)) || is_link($private)) { http_response_code(500); exit('Diretório privado indisponível.'); }
@chmod($private,0700);
$path=tempnam($private,'ug_backup_');
if ($path===false) { http_response_code(500); exit('Backup indisponível.'); }
$zip=new ZipArchive();
try {
 if ($zip->open($path,ZipArchive::OVERWRITE)!==true) throw new RuntimeException('Não foi possível iniciar backup.');
 $it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::LEAVES_ONLY);
 foreach ($it as $file) {
  if (!$file->isFile() || $file->isLink()) continue;
  $full=$file->getPathname();
  $rel=str_replace('\\','/',substr($full,strlen($root)+1));
  // Não exportar backups anteriores, travas, segredos ambientais ou pastas de controle.
  if (preg_match('~(^|/)(backups|\.git|node_modules|vendor)(/|$)~i',$rel) || preg_match('~(^|/)(\.env(?:\..*)?|\.ug_update\.lock)$~i',$rel)) continue;
  if (!$zip->addFile($full,$rel)) throw new RuntimeException('Falha ao adicionar arquivo.');
 }
 if (!$zip->close()) throw new RuntimeException('Falha ao concluir backup.');
 clearstatcache(true,$path);
 if (!is_file($path) || filesize($path)<22) throw new RuntimeException('Backup vazio.');
 $name='backup_manual_'.date('Y-m-d_H-i-s').'.zip';
 header('Content-Type: application/zip');
 header('Content-Disposition: attachment; filename="'.$name.'"');
 header('Cache-Control: no-store, private');
 header('X-Content-Type-Options: nosniff');
 header('Content-Length: '.filesize($path));
 readfile($path);
} catch (Throwable $e) { if (!headers_sent()) http_response_code(500); error_log('UniGestor backup: '.$e->getMessage()); }
finally { @unlink($path); }
