<?php
require __DIR__ . '/../src/Jcwx.php';
if($_GET['res']){
    var_dump($_GET['res']);
    exit;
}
$jcwx=new \jcwxSdk\Jcwx('http://192.168.10.249:8101','gmc','UjuGB6cwByEt0dS9');
header('location:'.$jcwx->generateLocationUrl('http://192.168.10.249:8100'));