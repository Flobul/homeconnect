<?php
require_once dirname(__FILE__) . "/../../../../core/php/core.inc.php";
include_file('core', 'authentification', 'php');
log::add('homeconnect', 'debug',"┌────────── Callback");

if (!jeedom::apiAccess(init('apikey'), 'homeconnect')) {
	echo 'Clef API non valide, vous n\'êtes pas autorisé à effectuer cette action';
	die();
}
if (!cache::exist('homeconnect::state')) {
	echo 'Vous ne pouvez appeler cette page sans être connecté. Veuillez vous connecter à votre Jeedom <a href=' . trim(network::getNetworkAccess()) . '/index.php>ici</a> avant et refaire l\'opération de connexion à Home Connect';
	die();
}
$state = cache::byKey('homeconnect::state')->getValue();

if (empty($_GET['state']) || !isset($state) || $_GET['state'] !== $state) {
	if (cache::exist('homeconnect::state')) {
        cache::delete('homeconnect::state');
    }
	exit('Invalid state');
}
cache::delete('homeconnect::state');

config::save('auth', init('code'), 'homeconnect');
log::add('homeconnect', 'debug', "│ Code d'autorisation sauvegardé.");
homeconnect::tokenRequest();
log::add('homeconnect', 'debug',"└────────── Fin de Callback");
redirect(trim(network::getNetworkAccess('external')) . '/index.php?v=d&p=plugin&id=homeconnect');
