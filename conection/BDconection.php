<?php


function BD(){
	include 'env.php';
	require 'vendor/autoload.php';
	$f3 = \Base::instance();
	$db=new DB\SQL(
		'mysql:host=localhost;port='.$config['port'].';dbname='.$config['dbname'],
		$config['user'],
		$config['password']
	);
	return $db;
}
?>