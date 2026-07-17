<?php
require_once dirname(__FILE__) . "/../../core/php/core.inc.php";
include_file('core', 'authentification', 'php');

function homeconnectMaskLogValue($_value, $_visibleCharacters = 3) {
	$value = (string) $_value;
	$length = strlen($value);
	if ($length === 0) {
		return 'longueur=0, valeur=[vide]';
	}
	if ($length <= ($_visibleCharacters * 2)) {
		return 'longueur=' . $length . ', valeur=[masquée]';
	}
	return 'longueur=' . $length . ', valeur=' . substr($value, 0, $_visibleCharacters) . '...' . substr($value, -$_visibleCharacters);
}

$callbackState = init('state');
$authorizationCode = init('code');
$apiKey = init('k');
$hasStoredState = cache::exist('homeconnect::state');
$storedState = $hasStoredState ? cache::byKey('homeconnect::state')->getValue() : '';

log::add('homeconnect', 'debug',"┌────────── Callback");
log::add('homeconnect', 'debug', '│ state : ' . homeconnectMaskLogValue($callbackState));
log::add('homeconnect', 'debug', '│ stored state : ' . homeconnectMaskLogValue($storedState));
log::add('homeconnect', 'debug', '│ code : ' . homeconnectMaskLogValue($authorizationCode));
log::add('homeconnect', 'debug', '│ apikey : ' . homeconnectMaskLogValue($apiKey));

if (!jeedom::apiAccess($apiKey, 'homeconnect')) {
	echo 'Clef API non valide, vous n\'êtes pas autorisé à effectuer cette action';
	die();
}
if (!$hasStoredState) {
	echo 'Vous ne pouvez appeler cette page sans être connecté. Veuillez vous connecter à votre Jeedom <a href=' . trim(network::getNetworkAccess()) . '/index.php>ici</a> avant et refaire l\'opération de connexion à Home Connect';
	die();
}

if (empty($callbackState) || !isset($storedState) || $callbackState !== $storedState) {
	if (cache::exist('homeconnect::state')) {
        cache::delete('homeconnect::state');
    }
	exit('Invalid state');
}
cache::delete('homeconnect::state');

config::save('auth', $authorizationCode, 'homeconnect');
log::add('homeconnect', 'debug', "│ Code d'autorisation sauvegardé.");
homeconnect::tokenRequest();
log::add('homeconnect', 'debug',"└────────── Fin de Callback");
redirect(trim(network::getNetworkAccess('external')) . '/index.php?v=d&p=plugin&id=homeconnect');
