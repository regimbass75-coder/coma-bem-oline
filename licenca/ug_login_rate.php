<?php
// Janela móvel de tentativas: escrita serializada com flock; dados não públicos.
function ug_login_rate($login, $success=false):bool {
 ensure_data();
 $ip=(string)($_SERVER['REMOTE_ADDR']??'unknown');
 $key=hash('sha256',$ip.'|'.strtolower(trim((string)$login)));
 $file=DATA_DIR.'/.login_rate_'.$key.'.json';
 $fp=@fopen($file,'c+');
 if(!$fp)return false; // falha fechada
 try{
  if(!flock($fp,LOCK_EX))return false;
  $raw=stream_get_contents($fp);
  $v=json_decode($raw?:'{}',true);
  $now=time();$start=(int)($v['start']??0);$n=(int)($v['failures']??0);
  if($start<=$now-900 || $start>$now){$start=$now;$n=0;}
  if($success){$n=0;$start=$now;}
  else $n++;
  rewind($fp);ftruncate($fp,0);
  $encoded=json_encode(['start'=>$start,'failures'=>$n]);
  if(fwrite($fp,$encoded)!==strlen($encoded)||!fflush($fp))return false;
  return $success || $n<=5;
 }finally{flock($fp,LOCK_UN);fclose($fp);}
}
function ug_login_rate_check($login):bool {
 ensure_data();
 $key=hash('sha256',(string)($_SERVER['REMOTE_ADDR']??'unknown').'|'.strtolower(trim((string)$login)));
 $file=DATA_DIR.'/.login_rate_'.$key.'.json';
 if(!is_file($file))return true;
 $fp=@fopen($file,'r');if(!$fp)return false;
 try{if(!flock($fp,LOCK_SH))return false;$v=json_decode(stream_get_contents($fp)?:'{}',true);
  return (int)($v['start']??0)<=time()-900 || (int)($v['failures']??0)<5;
 }finally{flock($fp,LOCK_UN);fclose($fp);}
}
