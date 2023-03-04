<?php
/* This file is part of Jeedom.
 *
 * Jeedom is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Jeedom is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Jeedom. If not, see <http://www.gnu.org/licenses/>.
*/

/** *************************** Includes ********************************** */

require_once dirname(__FILE__) . '/../../../../core/php/core.inc.php';
require_once __DIR__ . '/../../../../plugins/homeconnect/core/class/homeconnect.capabilities.php';

class homeconnect extends eqLogic {

    /** *************************** Constantes ******************************** */

    const API_AUTH_URL = "/security/oauth/authorize"; //?client_id=XXX&redirect_uri=XXX&response_type=code&scope=XXX&state=XXX
    const API_TOKEN_URL = "/security/oauth/token"; //client_id=XXX&redirect_uri=XXX&grant_type=authorization_code&code=XXX
    const API_REQUEST_URL = "/api/homeappliances";
    const API_EVENTS_URL = "/api/homeappliances/events";

    /** *************************** Attributs statiques *********************** */

    public static $_widgetPossibility = array(
        'custom' => true
    );

    /** *************************** Méthodes statiques ************************ */

    public static function getCmdValueTranslation($_key, $_value) {
        /**
         * Récupère la traduction de la valeur d'une commande
         *
         * @param	$_key		string		Clé de la commande
         * @param	$_value		string		Valeur brute de la clé
         * @return	$return		string		Valeur traduite de la clé
         */
        $return = $_value;
        $table = new homeconnect_capabilities();
        $tableData = $table->appliancesCapabilities;
        if (array_key_exists($_key, $tableData)) {
            if (array_key_exists('enum', $tableData[$_key])) {
                if (array_key_exists($_value, $tableData[$_key]['enum'])) {
                    $return = $tableData[$_key]['enum'][$_value]['name'];
                }
            } elseif (array_key_exists($_value, $tableData)) {
                $return = $tableData[$_value]['name'];
            } else {
                log::add(__CLASS__, 'debug', __FUNCTION__ . __(' La clé ', __FILE__) . $_key . __(' existe, mais la valeur ', __FILE__) . $_value . __(' est introuvable', __FILE__));
            }
        } else {
            log::add(__CLASS__, 'debug', __FUNCTION__ . __(' La clé ', __FILE__) . $_key . __(' est introuvable', __FILE__));
        }
        return $return;
    }

    public static function getCmdDetailTranslation($_key, $_detail) {
        /**
         * Récupère la traduction du nom d'une commande
         *
         * @param	$_key		string		Clé de la commande
         * @return	$return		string		Valeur traduite de la clé
         */
        $table = new homeconnect_capabilities();
        $tableData = $table->appliancesCapabilities;
        if (isset($tableData[$_key])) {
            return $tableData[$_key][$_detail];
        } else {
            return $_key;
            log::add(__CLASS__, 'debug', __FUNCTION__ . __(' La clé ', __FILE__) . $_key . __(' est introuvable', __FILE__));
        }
        return false;
    }

    public static function deamon_info() {
        /**
         * Récupère les infos d'état démon
         *
         * @return	$return		string		Etat du démon
         */
        $return = array();
        $return['log'] = 'homeconnect';
        $return['state'] = 'nok';
        $pid = trim(shell_exec('ps ax | grep "/homeconnectd.php" | grep -v "grep" | wc -l'));
        if ($pid != '' && $pid != '0') {
            $return['state'] = 'ok';
        }
        if (config::byKey('client_id', 'homeconnect', '') != '' && config::byKey('client_secret', 'homeconnect', '') != '') {
            $return['launchable'] = 'ok';
        } else {
            $return['launchable'] = 'nok';
            $return['launchable_message'] = __('Le client ou la clé ne sont pas configurés', __FILE__);
        }
        return $return;
    }

    public static function deamon_start($_debug = false) {
        /**
         * Lance le démon et retourne l'état
         *
         * @param $_debug		bool		mpode debug
         * @return	 		bool		Etat du lancement du démon
         */
        log::add(__CLASS__, 'info', __('Lancement du service homeconnect', __FILE__));
        $deamon_info = self::deamon_info();
        if ($deamon_info['launchable'] != 'ok') {
            throw new Exception(__('Veuillez vérifier la configuration', __FILE__));
        }
        if ($deamon_info['state'] == 'ok') {
            self::deamon_stop();
            sleep(2);
        }
        log::add('homeconnectd', 'info', __('Lancement du démon homeconnect', __FILE__));
        $cmd = substr(dirname(__FILE__) , 0, strpos(dirname(__FILE__) , '/core/class')) . '/resources/homeconnectd.php';
        log::add('homeconnectd', 'debug', __('Commande du daemon ', __FILE__) . $cmd);

        $result = exec('sudo php ' . $cmd . ' >> ' . log::getPathToLog('homeconnectd') . ' 2>&1 &');
        if (strpos(strtolower($result) , 'error') !== false || strpos(strtolower($result) , 'traceback') !== false) {
            log::add('homeconnectd', 'error', __('Daemon en erreur ', __FILE__) . $result);
            return false;
        }
        sleep(1);
        $i = 0;
        while ($i < 30) {
            $deamon_info = self::deamon_info();
            if ($deamon_info['state'] == 'ok') {
                break;
            }
            sleep(1);
            $i++;
        }
        if ($i >= 30) {
            log::add('homeconnectd', 'error', __('Impossible de lancer le démon homeconnectd ', __FILE__));
            return false;
        }
        log::add('homeconnectd', 'info', __('Démon homeconnectd lancé', __FILE__));
        return true;
    }

    public static function deamon_stop() {
        /**
         * Arrête le démon et retourne l'état
         *
         * @return	 		bool		Etat du démon
         */
        log::add('homeconnectd', 'info', __('Arrêt du service homeconnect', __FILE__));
        $cmd = '/homeconnectd.php';
        exec('sudo kill -9 $(ps aux | grep "' . $cmd . '" | awk \'{print $2}\')');
        sleep(1);
        exec('sudo kill -9 $(ps aux | grep "' . $cmd . '" | awk \'{print $2}\')');
        sleep(1);
        $deamon_info = self::deamon_info();
        if ($deamon_info['state'] == 'ok') {
            exec('sudo kill -9 $(ps aux | grep "' . $cmd . '" | awk \'{print $2}\')');
            sleep(1);
        } else {
            return true;
        }
        $deamon_info = self::deamon_info();
        if ($deamon_info['state'] == 'ok') {
            exec('sudo kill -9 $(ps aux | grep "' . $cmd . '" | awk \'{print $2}\')');
            sleep(1);
            return true;
        }
        log::add('homeconnectd', 'info', __('Service homeconnect arrêté', __FILE__));
    }

    public static function baseUrl() {
        /**
         * Renvoie l'url de test ou de production
         *
         * @return	 		string		URL de test ou production
         */
        if (config::byKey('demo_mode', 'homeconnect')) {
            return 'https://simulator.home-connect.com';
        } else {
            return 'https://api.home-connect.com';
        }
    }

    protected static function buildQueryString(array $params) {
        /**
         * Renvoie la requete en une url
         *
         * @return	 		string		URL contenant la requête
         */
        return http_build_query($params, null, '&', PHP_QUERY_RFC3986);
    }

    public static function lastSegment($separator, $key) {
        /**
         * Renvoie le dernier segement de l'url contenant le type
         *
         * @return	 		string		type
         */
        if (strpos($key, $separator) === false) {
            return '';
        }
        $parts = explode($separator, $key);
        return $parts[count($parts) - 1];
    }

    public static function firstSegment($separator, $key) {
        /**
         * Renvoie le premier segement de l'url contenant le type
         *
         * @return	 		string		type
         */
        if (strpos($key, $separator) === false) {
            return '';
        }
        $parts = explode($separator, $key);
        return $parts[0];
    }

    public static function request($url, $payload = null, $method = 'POST', $headers = array()) {
        /**
         * Renvoie le premier segement de l'url contenant le type
         *
         * @param	$url			string  URL à requeter
         * @param	$payload	array		Données à envoyer
         * @param	$method		string	PUT, GET, DELETE ou POST
         * @param	$headers	array   A inclure en plus des headers nécessaires
         * @return	$result		array		Résultat de la requête (json)
         */
        $ch = curl_init(self::baseUrl() . $url);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);

        $requestHeaders = array(
            'Accept: application/vnd.bsh.sdk.v1+json',
            'Accept-Language: ' . config::byKey('language', 'core', 'fr_FR'),
            'Authorization: Bearer ' . config::byKey('access_token', 'homeconnect')
        );

        if ($method == 'POST' || $method == 'PUT') {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
            $requestHeaders[] = 'Content-Type: application/json';
            $requestHeaders[] = 'Content-Length: ' . strlen($payload);
        }

        if (count($headers) > 0) {
            $requestHeaders = array_merge($requestHeaders, $headers);
        }

        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $requestHeaders);
        $result = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $totalRequests = intval(cache::byKey('homeconnect::requests::total')->getValue());
        $totalRequests++;
        cache::set('homeconnect::requests::total', $totalRequests, '');
        log::add(__CLASS__, 'debug', __('Nombre de requêtes envoyées aujourd\'hui ', __FILE__) . $totalRequests);

        if ($code == '200' || $code == '204') {
            log::add(__CLASS__, 'debug', __('La requête ', __FILE__) . $method . ' : ' . $url . __(' a réussi, code ', __FILE__) . $code . __(', résultat ', __FILE__) . $result);
            return $result;
        } else {
            // Traitement des erreurs
            log::add(__CLASS__, 'debug', __('La requête ', __FILE__) . $method . ' : ' . $url . __(' a retourné un code d\'erreur ', __FILE__) . $code . __(', résultat ', __FILE__) . $result);
            switch ($code) {
                case 400:
                    // "Bad Request", desc: "Error occurred (e.g. validation error - value is out of range)"
                break;
                case 401:
                    // "Unauthorized", desc: "No or invalid access token"
                    log::add(__CLASS__, 'debug', __('Le jeton d\'authentification au serveur est absent ou invalide. Reconnectez-vous', __FILE__));
                break;
                case 403:
                    // Forbidden", desc: "Scope has not been granted or home appliance is not assigned to HC account"
                    log::add(__CLASS__, 'debug', __('Accès à cette ressource non autorisé ou appareil non lié à cet utilisateur', __FILE__));
                break;
                case 404:
                    $result = json_decode($result, true);
                    if ($result['error']['key'] == 'SDK.Error.NoProgramActive' || $result['error']['key'] == 'SDK.Error.NoProgramSelected' || $result['error']['key'] == 'SDK.Error.UnsupportedProgram') {
                        return $result['error']['key'];
                    }
                    // Not Found", desc: "This resource is not available (e.g. no images on washing machine)"
                    log::add(__CLASS__, 'debug', __('Cette ressource n\'est pas disponible', __FILE__));
                break;
                case 405:
                    // "Method not allowed", desc: "The HTTP Method is not allowed for this resource" },
                    log::add(__CLASS__, 'debug', __('La méthode n\'est pas permise pour cette ressource', __FILE__) . $method);
                break;
                case 406:
                    // "Not Acceptable", desc: "The resource identified by the request is only capable of generating response entities which have content characteristics not acceptable according to the accept headers sent in the request."
                    log::add(__CLASS__, 'debug', __('Impossible de fournir une réponse, les entêtes "Accept" de la requête ne sont pas acceptés', __FILE__));
                break;
                case 408:
                    // "Request Timeout", desc: "API Server failed to produce an answer or has no connection to backend service"
                    log::add(__CLASS__, 'debug', __('Le serveur n\'a pas fourni de réponse dans le temps imparti', __FILE__));
                break;
                case 409:
                    // "Conflict", desc: "Command/Query cannot be executed for the home appliance, the error response contains the error details"
                    $result = json_decode($result, true);
                    $errorMsg = isset($result['error']['description']) ? $result['error']['description'] : '';
                    log::add(__CLASS__, 'error', __('Cette action ne peut pas être exécutée pour cet appareil ', __FILE__) . $errorMsg);
                break;
                case 415:
                    // "Unsupported Media Type", desc: "The request's Content-Type is not supported"
                    log::add(__CLASS__, 'debug', __('Le type de contenu de la requête n\'est pas pris en charge', __FILE__));
                break;
                case 429:
                    //	"Too Many Requests", desc: "E.g. the number of requests for a specific endpoint exceeded the quota of the client"
                    throw new \Exception(__('Vous avez dépassé le nombre de requêtes permises au serveur. Réessayez dans 24h ', __FILE__) . cache::byKey('homeconnect::requests::total')->getValue());
                case 500:
                    // "Internal Server Error", desc: "E.g. in case of a server configuration error or any errors in resource files"
                    log::add(__CLASS__, 'debug', __('Erreur interne du serveur', __FILE__));
                break;
                case 503:
                    // "Service Unavailable", desc: "E.g. if a required backend service is not available"
                    log::add(__CLASS__, 'debug', __('Service indisponible', __FILE__));
                break;
                default:
                    // Erreur inconnue
                    log::add(__CLASS__, 'debug', __('Erreur inconnue, code ', __FILE__) . $code);
            }
            return false;
        }
    }

    public static function syncHomeConnect($_forced) {
        /**
         * Connexion au compte Home Connect (via token) et récupération des appareils liés.
         *
         * @param			|*Cette fonction ne retourne pas de valeur*|
         * @return			|*Cette fonction ne retourne pas de valeur*|
         */
        log::add(__CLASS__, 'debug', __('Début ', __FILE__) . __FUNCTION__);
        if (empty(config::byKey('auth', 'homeconnect'))) {
            log::add(__CLASS__, 'debug', __('Erreur : Code d’authentification vide', __FILE__));
            throw new Exception(__('Erreur : Veuillez vous connecter à votre compte Home Connect via le menu configuration du plugin', __FILE__));
            return;
        }

        // Pas besoin de vérifier le token, homeappliances le fait
        // Récupération des appareils.
        self::homeappliances($_forced);

        log::add(__CLASS__, 'debug', __('Fin ', __FILE__) . __FUNCTION__);
    }

    public static function updateAppliances() {
        /**
         * Lance la mise à jour des informations des appareils (lancement par cron).
         *
         * @param			|*Cette fonction ne retourne pas de valeur*|
         * @return			|*Cette fonction ne retourne pas de valeur*|
         */

        log::add(__CLASS__, 'debug', __('Début ', __FILE__) . __FUNCTION__);

        self::verifyToken(60);

        // MAJ du statut de connexion des appareils.
        self::majConnected();

        foreach (eqLogic::byType('homeconnect') as $eqLogic) {
            // MAJ des programmes en cours.
            $eqLogic->updateProgram();
            // MAJ des états
            $eqLogic->updateStates();
            // MAJ des réglages
            $eqLogic->updateSettings();
            if ($eqLogic->getIsEnable()) {
                $eqLogic->refreshWidget();
            }
        }
        log::add(__CLASS__, 'debug', __('Fin ', __FILE__) . __FUNCTION__);
    }

    public static function authRequest() {
        /**
         * Construit l'url d'authentification.
         *
         * @param			|*Cette fonction ne prend pas de paramètres*|
         * @return			|*Cette fonction retourne l'url d'authentification*|
         */
        log::add(__CLASS__, 'debug', __('Début ', __FILE__) . __FUNCTION__);
        @session_start();
        $authorizationUrl = self::baseUrl() . self::API_AUTH_URL;
        $clientId = config::byKey('client_id', 'homeconnect', '', true);
        $redirectUri = urlencode(trim(network::getNetworkAccess('external')) . '/plugins/homeconnect/core/php/callback.php?apikey=' . jeedom::getApiKey('homeconnect'));
        if (config::byKey('demo_mode', 'homeconnect')) {
            $parameters['scope'] = implode(' ', ['IdentifyAppliance', 'Monitor', 'Settings', 'CoffeeMaker-Control', 'Dishwasher-Control', 'Dryer-Control', 'Washer-Control']);
            $parameters['user'] = 'me'; // Can be anything non-zero length
            $parameters['client_id'] = config::byKey('demo_client_id', 'homeconnect', '', true);
        } else {
            $parameters['scope'] = implode(' ', ['IdentifyAppliance', 'Monitor', 'Settings', 'Control']);
            $parameters['redirect_uri'] = trim(network::getNetworkAccess('external')) . '/plugins/homeconnect/core/php/callback.php?apikey=' . jeedom::getApiKey('homeconnect');
            $parameters['client_id'] = config::byKey('client_id', 'homeconnect', '', true);
        }
        $parameters['response_type'] = 'code';
        $state = bin2hex(random_bytes(16));
        $_SESSION['oauth2state'] = $state;
        $parameters['state'] = $state;
        cache::set('homeconnect::state', $state, 600);
        // Construction de l'url.
        $url = $authorizationUrl . "?" . self::buildQueryString($parameters);
        log::add(__CLASS__, 'debug', "Url : " . $url);
        log::add(__CLASS__, 'debug', __('Fin ', __FILE__) . __FUNCTION__);
        return $url;
    }

    public static function authDemoRequest() {
        /**
         * Récupère un code d'authorisation à échanger contre un token.
         *
         * @param			|*Cette fonction ne retourne pas de valeur*|
         * @return			|*Cette fonction ne retourne pas de valeur*|
         */

        log::add(__CLASS__, 'debug', __('Début ', __FILE__) . __FUNCTION__);

        // Construction de l'url.
        $url = self::authRequest();

        // Envoie d'une requête GET et récupération du header.
        $curl = curl_init();
        $options = [CURLOPT_URL => $url, CURLOPT_RETURNTRANSFER => True, CURLOPT_SSL_VERIFYPEER => False, CURLOPT_HEADER => True, CURLINFO_HEADER_OUT => true, ];
        curl_setopt_array($curl, $options);
        $response = curl_exec($curl);
        $info = curl_getinfo($curl);
        curl_close($curl);

        // Vérification du code réponse.
        if ($info['http_code'] != 302) {
            // Récupération du message d'erreur pour log.
            preg_match("/[\{].*[\}]/", $response, $matches);
            log::add(__CLASS__, 'debug', __('Erreur : Code erreur ', __FILE__) . $info['http_code'] . ' : ' . print_r($matches, true));
            throw new Exception("Erreur : " . print_r($matches));
            return;
        }

        $params = parse_url($info['redirect_url']); // Récupération de l'url de redirection avec paramêtre.
        $params = explode("&", $params['query']); // Explode des paramêtres de l'url afin d'isoler l'authorize code.
        // Récupération du code d'authorisation.
        foreach ($params as $key => $value) {
            $explode = explode("=", $value);

            if ($explode[0] == "code") {
                config::save('auth', $explode[1], 'homeconnect');
                log::add(__CLASS__, 'debug', __('Code d\'authorisation récupéré ', __FILE__) . $explode[1]);
                homeconnect::tokenRequest();
            }
        }

        log::add(__CLASS__, 'debug', __('Fin ', __FILE__) . __FUNCTION__);
    }

    public static function tokenRequest() {
        /**
         * Récupère un token permettant l'accès au serveur.
         *
         * @param			|*Cette fonction ne prend pas de paramètres*|
         * @return			|*Cette fonction ne retourne pas de valeur*|
         */

        log::add(__CLASS__, 'debug', __('Début ', __FILE__) . __FUNCTION__);
        if (!config::byKey('demo_mode', 'homeconnect')) {
            $clientId = config::byKey('client_id', 'homeconnect', '', true);
        } else {
            $clientId = config::byKey('demo_client_id', 'homeconnect', '', true);
        }
        // Vérification de la présence du code d'authorisation avant de demander le token.
        if (empty(config::byKey('auth', 'homeconnect'))) {
            log::add(__CLASS__, 'debug', __('Erreur : Code d’authentification vide', __FILE__));
            throw new Exception("Erreur : Veuillez connecter votre compte via le menu configuration du plugin.");
            return;
        }
        $url = self::baseUrl() . self::API_TOKEN_URL;
        log::add(__CLASS__, 'debug', "Url : " . $url);

        // Création du paramêtre POSTFIELDS.
        $parameters = array();
        $parameters['client_id'] = $clientId;
        if (!config::byKey('demo_mode', 'homeconnect')) {
            $parameters['client_secret'] = config::byKey('client_secret', 'homeconnect', '', true);
        }
        $parameters['redirect_uri'] = trim(network::getNetworkAccess('external')) . '/plugins/homeconnect/core/php/callback.php?apikey=' . jeedom::getApiKey('homeconnect');
        $parameters['grant_type'] = 'authorization_code';
        $parameters['code'] = config::byKey('auth', 'homeconnect');
        log::add(__CLASS__, 'debug', "Post fields : " . json_encode($parameters));

        // Récupération du Token.
        $curl = curl_init();
        $options = [CURLOPT_URL => $url, CURLOPT_RETURNTRANSFER => True, CURLOPT_SSL_VERIFYPEER => false, CURLOPT_POST => True, CURLOPT_POSTFIELDS => self::buildQueryString($parameters) , ];
        curl_setopt_array($curl, $options);
        $response = json_decode(curl_exec($curl) , true);
        log::add(__CLASS__, 'debug', "Response = " . print_r($response, true));
        $http_code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        curl_close($curl);

        // Vérification du code réponse.
        if ($http_code != 200) {
            log::add(__CLASS__, 'debug', __('Erreur : Code erreur ', __FILE__) . $http_code . ' : ' .__('Impossible de récupérer le token', __FILE__));
            throw new Exception("Erreur : Impossible de récupérer le token (code erreur : " . $http_code . ").");
            return;
        } else {
            log::add(__CLASS__, 'debug', __('Token récupéré', __FILE__));
        }

        // Calcul de l'expiration du token.
        $expires_in = time() + $response['expires_in'];

        // Enregistrement des informations dans le plugin.
        config::save('access_token', $response['access_token'], 'homeconnect');
        config::save('refresh_token', $response['refresh_token'], 'homeconnect');
        config::save('token_type', $response['token_type'], 'homeconnect');
        config::save('scope', $response['scope'], 'homeconnect');
        config::save('expires_in', $expires_in, 'homeconnect');
        config::save('id_token', $response['id_token'], 'homeconnect');

        log::add(__CLASS__, 'debug', 'Access token : ' . $response['access_token']);
        log::add(__CLASS__, 'debug', 'Refresh token : ' . $response['refresh_token']);
        log::add(__CLASS__, 'debug', 'Token type : ' . $response['token_type']);
        log::add(__CLASS__, 'debug', 'Scope : ' . $response['scope']);
        log::add(__CLASS__, 'debug', 'Expires in : ' . $expires_in);
        log::add(__CLASS__, 'debug', 'Id token : ' . $response['id_token']);
        log::add(__CLASS__, 'debug', __('Fin ', __FILE__) . __FUNCTION__);
    }

    public static function tokenRefresh() {
        /**
         * Rafraichit un token expiré permettant l'accès au serveur.
         *
         * @param			|*Cette fonction ne prend pas de paramètres*|
         * @return			|*Cette fonction ne retourne pas de valeur*|
         */

        log::add(__CLASS__, 'debug', __('Début ', __FILE__) . __FUNCTION__);

        // Vérification de la présence du code d'authorisation avant de demander le token.
        if (empty(config::byKey('auth', 'homeconnect'))) {
            log::add(__CLASS__, 'debug', __('Erreur : Code d’authentification vide', __FILE__));
            throw new Exception("Erreur : Veuillez connecter votre compte via le menu configuration du plugin.");
            return;
        }
        $url = self::baseUrl() . self::API_TOKEN_URL;
        log::add(__CLASS__, 'debug', "Url : " . $url);

        // Création du paramêtre POSTFIELDS.
        $parameters = array();
        $parameters['grant_type'] = 'refresh_token';
        if (!config::byKey('demo_mode', 'homeconnect')) {
            $parameters['client_secret'] = config::byKey('client_secret', 'homeconnect', '', true);
        }
        $parameters['refresh_token'] = config::byKey('refresh_token', 'homeconnect', '', true);
        log::add(__CLASS__, 'debug', "Post fields : " . json_encode($parameters));

        // Récupération du Token.
        $curl = curl_init();
        $options = [CURLOPT_URL => $url, CURLOPT_RETURNTRANSFER => True, CURLOPT_SSL_VERIFYPEER => false, CURLOPT_POST => True, CURLOPT_POSTFIELDS => self::buildQueryString($parameters) , ];
        curl_setopt_array($curl, $options);
        $response = json_decode(curl_exec($curl) , true);
        log::add(__CLASS__, 'debug', "Response : " . print_r($response, true));
        $http_code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        curl_close($curl);

        $tokenRequests = intval(cache::byKey('homeconnect::requests::refresh_token')->getValue());
        $tokenRequests++;
        cache::set('homeconnect::requests::refresh_token', $tokenRequests, '');

        // Vérification du code réponse.
        if ($http_code != 200) {
            log::add(__CLASS__, 'debug', __('Erreur : Code erreur ', __FILE__) . $http_code . ' : ' . __('Impossible de rafraichir le token', __FILE__));
            throw new Exception(__('Impossible de rafraichir le token', __FILE__));
            return;

        } else {

            log::add(__CLASS__, 'debug', __('Token rafraichi', __FILE__));
        }

        // Calcul de l'expiration du token.
        $expires_in = time() + $response['expires_in'];

        // Enregistrement des informations dans le plugin.
        config::save('access_token', $response['access_token'], 'homeconnect');
        config::save('refresh_token', $response['refresh_token'], 'homeconnect');
        config::save('token_type', $response['token_type'], 'homeconnect');
        config::save('scope', $response['scope'], 'homeconnect');
        config::save('expires_in', $expires_in, 'homeconnect');
        config::save('id_token', $response['id_token'], 'homeconnect');

        log::add(__CLASS__, 'debug', 'Access token : ' . $response['access_token']);
        log::add(__CLASS__, 'debug', 'Refresh token : ' . $response['refresh_token']);
        log::add(__CLASS__, 'debug', 'Token type : ' . $response['token_type']);
        log::add(__CLASS__, 'debug', 'Scope : ' . $response['scope']);
        log::add(__CLASS__, 'debug', 'Expires in : ' . $expires_in);
        log::add(__CLASS__, 'debug', 'Id token : ' . $response['id_token']);
        log::add(__CLASS__, 'debug', __('Fin ', __FILE__) . __FUNCTION__);
    }

    public static function verifyToken($delay) {
        /**
         * Vérification si le token est expiré, et demande d'un nouveau si expiré
         *
         * @param	$delay	int		Durée avant expiration
         * @return
         */
        if ((config::byKey('expires_in', 'homeconnect') - time()) < $delay) {
            log::add(__CLASS__, 'debug', __('Attention : Le token est expiré, renouvellement de ce dernier', __FILE__));
            // Récupération du token d'accès aux serveurs.
            // ne pas oublier d'arrêter le deamon avant
            self::deamon_stop();
            self::tokenRefresh();
            self::deamon_start();
        }

        // Vérification de la présence du token et tentative de récupération si absent.
        if (empty(config::byKey('access_token', 'homeconnect'))) {
            log::add(__CLASS__, 'debug', __('Attention : Le token  manquant, récupération de ce dernier', __FILE__));

            // Récupération du token d'accès aux serveurs.
            self::deamon_stop();
            self::tokenRequest();
            self::deamon_start();

            if (empty(config::byKey('access_token', 'homeconnect'))) {
                log::add(__CLASS__, 'debug', __('Erreur : La récupération du token a échoué', __FILE__));
                return;
            }
            // Dans le cas contraire relancer le deamon
        }
        // Relancer le deamon
    }

    private static function homeappliances($_forced) {
        /**
         * Récupère la liste des appareils connectés et création des objets associés.
         *
         * @param			|*Cette fonction ne retourne pas de valeur*|
         * @return			|*Cette fonction ne retourne pas de valeur*|
         */
        log::add(__CLASS__, 'debug', __('Début ', __FILE__) . __FUNCTION__ . __(', forcée : ', __FILE__) . $_forced);

        self::verifyToken(60);
        $startRequest = intval(cache::byKey('homeconnect::requests::total')->getValue());

        $response = self::request(self::API_REQUEST_URL, null, 'GET', array());
        $response = json_decode($response, true);
        foreach ($response['data']['homeappliances'] as $key => $appliance) {
            /*	haId = Id de l'appareil
            vib = modèle de l'appareil
            brand = marque de l'appareil
            type = type de l'appareil
            name = nom de l'appareil
            enumber = N° de série
            connected = boolean */

            // Vérification que l'appareil n'est pas déjà créé.
            $eqLogic = eqLogic::byLogicalId($appliance['haId'], 'homeconnect');

            if (!is_object($eqLogic)) {
                event::add('jeedom::alert', array(
                    'level' => 'warning',
                    'page' => 'homeconnect',
                    'message' => __("Nouvel appareil detecté", __FILE__) . ' ' . $appliance['name'],
                ));
                // Création de l'appareil.
                $eqLogic = new homeconnect();
                $eqLogic->setLogicalId($appliance['haId']);
                $eqLogic->setIsEnable(1);
                $eqLogic->setIsVisible(1);
                $defaultRoom = intval(config::byKey('defaultParentObject', 'homeconnect', '', true));
                if ($defaultRoom) $eqLogic->setObject_id($defaultRoom);
                $eqLogic->setEqType_name('homeconnect');
                $eqLogic->setName($appliance['name']);
                $eqLogic->setConfiguration('haid', $appliance['haId']);
                $eqLogic->setConfiguration('vib', $appliance['vib']);
                $eqLogic->setConfiguration('brand', $appliance['brand']);
                $eqLogic->setConfiguration('type', $appliance['type']);
                $eqLogic->save();
                $found_eqLogics = self::findProduct($appliance);
                $_forced = true; // forcer la récupération de tous les programmes/settings si l'appareil n'existe pas...

            }
            if (is_object($eqLogic)) {
                // certains apareils ne répondent pas pour les programmes et options s'ils ne sont pas connectés
                if ($appliance['connected'] && $_forced) {
                    // Programs
                    if ($appliance['type'] !== 'Refrigerator' && $appliance['type'] !== 'FridgeFreezer' && $appliance['type'] !== 'WineCooler') {
                        $programs = self::request(self::API_REQUEST_URL . '/' . $appliance['haId'] . '/programs', null, 'GET', array());
                        if ($programs !== false) {
                            $programs = json_decode($programs, true);
                            if (isset($programs['data']['programs'])) {
                                $eqLogic->setConfiguration('hasPrograms', true);
                                foreach ($programs['data']['programs'] as $applianceProgram) {
                                    $programdata = self::request(self::API_REQUEST_URL . '/' . $appliance['haId'] . '/programs/available/' . $applianceProgram['key'], null, 'GET', array());
                                    log::add(__CLASS__, 'debug', 'Appliance Program ' . print_r($programdata, true));
                                    if ($programdata !== false && $programdata !== 'SDK.Error.UnsupportedProgram') {
                                        $programdata = json_decode($programdata, true);
                                        if (isset($applianceProgram['constraints']['execution'])) {
                                            if ($applianceProgram['constraints']['execution'] !== 'selectandstart') {
                                                $path = 'programs/active';
                                            } else {
                                                $path = 'programs/selected';
                                            }
                                        } else {
                                            $path = 'programs/selected';
                                        }
                                        if (isset($programdata['data']['key'])) {
                                            // Création de la commande action programme
                                            $actionCmd = $eqLogic->createActionCmd($programdata['data'], $path, 'Program');
                                            if ($path == 'programs/selected') {
                                                $infoCmd = $eqLogic->getCmd('info', 'GET::BSH.Common.Root.SelectedProgram');
                                                if (is_object($infoCmd)) {
                                                    // On a trouvé la commande info associée.
                                                    log::add(__CLASS__, 'debug', __('setValue sur la commande programme selected ', __FILE__) . $actionCmd->getLogicalId() . __(' commande info ', __FILE__) . $infoCmd->getLogicalId());
                                                    $actionCmd->setValue($infoCmd->getId());
                                                    $actionCmd->save();
                                                } else {
                                                    log::add(__CLASS__, 'debug', __('Pas de commande info GET::BSH.Common.Root.SelectedProgram', __FILE__));
                                                }
                                            } else if ($path == 'programs/active') {
                                                $infoCmd = $eqLogic->getCmd('info', 'GET::BSH.Common.Root.ActiveProgram');
                                                if (is_object($infoCmd)) {
                                                    // On a trouvé la commande info associée.
                                                    log::add(__CLASS__, 'debug', __('setValue sur la commande programme active ', __FILE__) . $actionCmd->getLogicalId() . __(' commande info ', __FILE__) . $infoCmd->getLogicalId());
                                                    $actionCmd->setValue($infoCmd->getId());
                                                    $actionCmd->save();
                                                    // A voir : ne pas la rendre visible ?

                                                } else {
                                                    log::add(__CLASS__, 'debug', __('Pas de commande info GET::BSH.Common.Root.ActiveProgram', __FILE__));
                                                }
                                            }
                                        }
                                        if (isset($programdata['data']['options'])) {
                                            log::add(__CLASS__, 'debug', __('Création des commandes options ', __FILE__) . print_r($programdata['data']['options'], true) . ', path : ' . $path);
                                            // creation des commandes option action et info
                                            $opt = array();
                                            $cmdProgram = $eqLogic->getCmd('action', 'PUT::' . $programdata['data']['key']);
                                            foreach ($programdata['data']['options'] as $optionData) {
                                                array_push($opt, $optionData['key']);
                                                $cmdActionOption = $eqLogic->getCmd('action', 'PUT::' . $optionData['key']);
                                                $cmdInfoOption = $eqLogic->getCmd('info', 'GET::' . $optionData['key']);
                                                if (!is_object($cmdActionOption) && !is_object($cmdInfoOption)) {
                                                    log::add(__CLASS__, 'debug', __('Commandes options action et info inexistantes PUT::/GET::', __FILE__) . $optionData['key']);
                                                    $eqLogic->createProgramOption($path, $optionData);
                                                }
                                                if ((intval(cache::byKey('homeconnect::requests::total')->getValue()) - $startRequest) >= 49) {
                                                    sleep(61);
                                                    $startRequest = intval(cache::byKey('homeconnect::requests::total')->getValue());
                                                    event::add('jeedom::alert', array(
                                                        'level' => 'warning',
                                                        'page' => 'homeconnect',
                                                        'message' => __('Nombre de requêtes dépassé, pause de 60 secondes', __FILE__) ,
                                                    ));
                                                }
                                            }
                                            if (is_object($cmdProgram)) {
                                                $configOpt = array_merge($opt, $cmdProgram->getConfiguration('listOptions', array()));
                                                $configOpt = array_unique($configOpt);
                                                $cmdProgram->setConfiguration('listOptions', $configOpt)->save();
                                                log::add(__CLASS__, 'debug', __('Ajout des options disponibles dans la commande PUT::', __FILE__) . $programdata['data']['key'] . print_r($configOpt, true));
                                            }
                                        } else {
                                            log::add(__CLASS__, 'debug', __('Aucune commande option', __FILE__));
                                        }
                                    } else {
                                        log::add(__CLASS__, 'debug', __('La requête /programs/available/ a retourné false', __FILE__));
                                    }
                                }
                            } else {
                                log::add(__CLASS__, 'debug', __('Cet appareil n\'a pas de programmes', __FILE__));
                                $eqLogic->setConfiguration('hasPrograms', false);
                            }
                        } else {
                            log::add(__CLASS__, 'debug', __('La requête /programs a retourné false', __FILE__));
                            $eqLogic->setConfiguration('hasPrograms', false);
                        }
                    } else {
                        log::add(__CLASS__, 'debug', __('Ce type d\'appareil n\'a pas de programme', __FILE__));
                        $eqLogic->setConfiguration('hasPrograms', false);
                    }

                    if ((intval(cache::byKey('homeconnect::requests::total')
                        ->getValue()) - $startRequest) >= 49) {
                        sleep(61);
                        $startRequest = intval(cache::byKey('homeconnect::requests::total')->getValue());
                        event::add('jeedom::alert', array(
                            'level' => 'warning',
                            'page' => 'homeconnect',
                            'message' => __('Nombre de requêtes dépassé, pause de 60 secondes', __FILE__) ,
                        ));
                    }

                    // Status
                    $allStatus = self::request(self::API_REQUEST_URL . '/' . $appliance['haId'] . '/status', null, 'GET', array());
                    if ($allStatus !== false) {
                        $allStatus = json_decode($allStatus, true);
                        if (isset($allStatus['data']['status'])) {
                            foreach ($allStatus['data']['status'] as $statusData) {
                                log::add(__CLASS__, 'debug', 'Status ' . print_r($statusData, true));
                                $eqLogic->createInfoCmd($statusData, 'status/' . $statusData['key'], 'Status');
                            }
                        } else {
                            log::add(__CLASS__, 'debug', "Aucun status");
                        }
                    }

                    if ((intval(cache::byKey('homeconnect::requests::total')->getValue()) - $startRequest) >= 49) {
                        sleep(61);
                        $startRequest = intval(cache::byKey('homeconnect::requests::total')->getValue());
                        event::add('jeedom::alert', array(
                            'level' => 'warning',
                            'page' => 'homeconnect',
                            'message' => __('Nombre de requêtes dépassé, pause de 60 secondes', __FILE__) ,
                        ));
                    }

                    // Settings
                    $allSettings = self::request(self::API_REQUEST_URL . '/' . $appliance['haId'] . '/settings', null, 'GET', array());
                    log::add(__CLASS__, 'debug', __('tous les Settings ', __FILE__) . $allSettings);
                    if ($allSettings !== false) {
                        $allSettings = json_decode($allSettings, true);
                        if (isset($allSettings['data']['settings'])) {
                            foreach ($allSettings['data']['settings'] as $setting) {
                                log::add(__CLASS__, 'debug', 'setting key ' . $setting['key']);
                                $path = 'settings/' . $setting['key'];
                                $settingData = self::request(self::API_REQUEST_URL . '/' . $appliance['haId'] . '/' . $path, null, 'GET', array());
                                if ($settingData !== false) {
                                    log::add(__CLASS__, 'debug', 'Setting ' . $settingData);
                                    $settingData = json_decode($settingData, true);
                                    // A voir si pas d'access on assume readWrite. est-ce correct ?
                                    if (isset($settingData['data']['constraints']['access']) && $settingData['data']['constraints']['access'] == 'readWrite') {
                                        log::add(__CLASS__, 'debug', __('Le setting est readWrite, on crée aussi la commande setting action', __FILE__));
                                        $actionCmd = $eqLogic->createActionCmd($settingData['data'], $path, 'Setting');
                                        log::add(__CLASS__, 'debug', __('On crée aussi la commande setting info', __FILE__));
                                        $infoCmd = $eqLogic->createInfoCmd($settingData['data'], $path, 'Setting', $actionCmd);
                                        // le setValue est fait dans createInfoCmd
                                    } else {
                                        // Commande info sans commande action associée
                                        log::add(__CLASS__, 'debug', __('Le setting est non readWrite, on ne crée que la commande setting info', __FILE__));
                                        $infoCmd = $eqLogic->createInfoCmd($settingData['data'], $path, 'Setting');
                                    }
                                }
                            }
                        } else {
                            log::add(__CLASS__, 'debug', __('Aucun setting', __FILE__));
                        }
                    }
                } else {
                    if ($_forced) {
                        // L'appareil n'est pas connecté
                        event::add('jeedom::alert', array(
                            'level' => 'danger',
                            'page' => 'homeconnect',
                            'message' => __('L\'appareil n\'est pas connecté. Merci de le connecter et de refaire une synchronisation', __FILE__) ,
                        ));
                        sleep(3);
                    } else {
                        log::add(__CLASS__, 'debug', __('L\'appareil est connecté, mais les program/settings n\'ont pas été demandés', __FILE__));
                    }
                }
            } else {
                $eqLogic->applyModuleConfiguration(true);
            }
        }
        log::add(__CLASS__, 'debug', __('Fin  ', __FILE__) . __FUNCTION__);
    }

    private static function majConnected() {
        /**
         * Récupère le statut connecté des l'appareils.
         *
         * @param			|*Cette fonction ne retourne pas de valeur*|
         * @return			|*Cette fonction ne retourne pas de valeur*|
         */

        log::add(__CLASS__, 'debug', __('Début ', __FILE__) . __FUNCTION__);

        // A voir si l'appareil vient de se connecter n'y aurait-il pas des choses à faire ?
        $response = self::request(self::API_REQUEST_URL, null, 'GET', array());
        $response = json_decode($response, true);
        foreach ($response['data']['homeappliances'] as $key) {
            /* connected = boolean */

            $eqLogic = eqLogic::byLogicalId($key['haId'], 'homeconnect');
            if (is_object($eqLogic) && $eqLogic->getIsEnable()) {
                $cmd = $eqLogic->getCmd('info', 'connected');
                if (is_object($cmd)) {
                    $eqLogic->checkAndUpdateCmd($cmd, $key['connected']);

                    log::add(__CLASS__, 'debug', __('MAJ du status connected ', __FILE__) . $eqLogic->getConfiguration('type', '') . ' ' . $eqLogic->getConfiguration('haId', '') . __(' Valeur : ', __FILE__) . $key['connected'] ? __('Oui', __FILE__) : __('Non', __FILE__));

                } else {
                    log::add(__CLASS__, 'debug', __('Erreur : La commande connected n\'existe pas ', __FILE__) . $eqLogic->getConfiguration('type', '') . ' ' . $eqLogic->getConfiguration('haId', ''));
                }
            }
        }

        log::add(__CLASS__, 'debug', __('Fin ', __FILE__) . __FUNCTION__);
    }

    public static function findProduct($_appliance) {
        /**
         * Recherche l'équipement via les paramètres fournis
         *
         * @param	$_appliance		array			Tableau des paramètres de l'appareil
         * @return	$eqLogic		object		L'équipement
         */
        $eqLogic = self::byLogicalId($_appliance['haId'], __CLASS__);
        $eqLogic->loadCmdFromConf($_appliance['type']);
        return $eqLogic;
    }

    public static function devicesParameters($_type = '') {
        /**
         * Récupère les paramètre de commandes d'un type
         *
         * @param	$_type			string		Type d'appareil
         * @return	$return		array		Tableau de paramètres
         */
        $return = array();
        $file = dirname(__FILE__) . '/../config/types/' . $_type . '.json';
        if (!is_file($file)) {
            return false;
        }

        try {
            $content = file_get_contents($file);
            if (is_json($content)) {
                $return += json_decode($content, true);
            }
        }
        catch(Exception $e) {
            log::add(__CLASS__, 'info', __('Fichier erroné ', __FILE__) . $file);
        }
        return $return;
    }

    public static function getEvents($ch, $string) {
        /**
         * Récupère tous les évenements et instruit les commandes
         *
         * @param	$ch			objet		Session
         * @param	$string		string		Chaîne d'événement reçue
         * @return	$length		string		Longueur de la chaine.
         */
        $length = strlen($string);

        $isError = json_decode($string, true);
        if (is_array($isError) && array_key_exists('error', $isError)) {
            if (array_key_exists('key', $isError['error']) && $isError['error']['key'] == 'invalid_token') {
                log::add('homeconnectd', 'info', __('Régénération du token demandée', __FILE__));
                self::tokenRefresh();
                self::deamon_start();
            }
        }

        $events = array();
        log::add('homeconnectd', 'info', __('Événement brut reçu ', __FILE__) . $string);
        foreach (explode("\r\n", $string) as $line) {
            if (strstr($line, 'event:')) {
                $event = array(
                    'haId' => NULL,
                    'event' => NULL,
                    'data' => array()
                );
                foreach (explode("\n", $line) as $event_data) {
                    if (strstr($event_data, 'event:')) {
                        $event['event'] = trim(strtolower(substr($event_data, 6)));
                    } else if (strstr($event_data, 'id:')) {
                        $event['haId'] = trim(substr($event_data, 3));
                    } else if (strstr($event_data, 'data:')) {
                        if ($json = json_decode(trim(substr($event_data, 5)) , true)) {
                            $event['data'] = $json;
                        }
                    }
                }
                if ($event['haId']) {
                    $events[] = $event;
                }
            }
        }
        log::add('homeconnectd', 'info', __('Événements capturés ', __FILE__) . print_r($events, true));

        foreach ($events as $evenement) {
            if ($evenement['data'] && isset($evenement['data']['items'])) {
                foreach ($evenement['data']['items'] as $items) {
                    $eqLogic = eqLogic::byLogicalId($evenement['haId'], 'homeconnect');
                    if (is_object($eqLogic) && $eqLogic->getIsEnable()) {
                        $cat = 'Option';
                        $cmdLogicalId = 'GET::' . $items['key'];
                        //if (!isset($items['uri'])) continue;
                        if (isset($items['uri'])) {
                            $sections = explode('/', $items['uri']);
                            $path = implode('/', array(
                                $sections[4],
                                $sections[5]
                            ));
                            $cmdAction = $eqLogic->getCmd('action', 'PUT::' . $items['key']);
                            if ($sections[4] == 'settings') {
                                $cat = 'Setting';
                                if (!is_object($cmdAction)) {
                                    $settingData = self::request(self::API_REQUEST_URL . '/' . $evenement['haId'] . '/' . $path, null, 'GET', array());
                                    if ($settingData !== false) {
                                        log::add(__CLASS__, 'debug', 'Setting ' . $settingData);
                                        $settingData = json_decode($settingData, true);
                                        if (isset($settingData['data']['constraints']['access']) && $settingData['data']['constraints']['access'] == 'readWrite') {
                                            log::add(__CLASS__, 'debug', __('Le setting est readWrite, on crée aussi la commande setting action', __FILE__));
                                            $actionCmd = $eqLogic->createActionCmd($settingData['data'], $path, $cat);
                                            log::add(__CLASS__, 'debug', __('On crée aussi la commande setting info', __FILE__));
                                            $infoCmd = $eqLogic->createInfoCmd($settingData['data'], $path, $cat, $actionCmd);
                                        } else {
                                            // Commande info sans commande action associée
                                            log::add(__CLASS__, 'debug', __('Le setting est non readWrite, on ne crée que la commande setting info', __FILE__));
                                            $infoCmd = $eqLogic->createInfoCmd($settingData['data'], $path, $cat);
                                        }
                                    }
                                }
                            } elseif ($sections[4] == 'status') {
                                $cat = 'Status';
                            }
                        }
                        $cmd = $eqLogic->getCmd('info', $cmdLogicalId);
                        if (!is_object($cmd)) {
                            $eqLogic->createInfoCmd($items, $path, $cat);
                        }
                        $eqLogic->updateInfoCmdValue($cmdLogicalId, $items);
                    } else {
                        log::add(__CLASS__, 'debug', __('L\'appareil n\'existe pas ou n\'est pas activé ', __FILE__) . $array['haId']);
                    }
                }
            }
        }
        return $length; //important de renvoyer la taille

    }

    public static function deleteEqLogic() {
        /**
         * Supprime tous les équipements
         *
         * @return
         */
        foreach (eqLogic::byType(__CLASS__) as $eqLogic) {
            $eqLogic->remove();
        }
    }

    public static function cron() {
        /**
         * Cron à la minute de jeedom : mise à jour des appareils
         *
         * @return
         */
        $autorefresh = config::byKey('autorefresh', 'homeconnect');
        if ($autorefresh != '') {
            try {
                $c = new Cron\CronExpression(checkAndFixCron($autorefresh) , new Cron\FieldFactory);
                if ($c->isDue()) {
                    log::add(__CLASS__, 'debug', __('Cron écoulé', __FILE__));
                    self::updateAppliances();
                } else {
                    self::verifyToken(180);
                }
            }
            catch(Exception $exc) {
                log::add(__CLASS__, 'error', __('Erreur lors de l\'exécution du cron ', __FILE__) . $exc->getMessage());
            }
        }
    }

    public static function cronDaily() {
        /**
         * Cron au jour de jeedom : remise à zéro des compteurs de requêtes
         *
         * @return
         */
        cache::set('homeconnect::requests::total', 0, '');
        cache::set('homeconnect::requests::refresh_token', 0, '');
    }

    public static function setCmdName($_key, $_cmdData) {
        /**
         * Renvoie le nom de la commande parmi le dico ou la valeur traduite reçue de homeconnect
         *
         * @param $_key			string  Clé à traduire
         * @param $_cmdData	array 	Tableau reçu contenant valeur, traduction...
         * @return 					string  Clé traduite
         */
        $nameNewTrans = self::getCmdDetailTranslation($_key, 'name');
        if (isset($nameNewTrans)) {
            return $nameNewTrans;
        } else if (array_key_exists('displayvalue', $_cmdData)) {
            return $_cmdData['displayvalue'];
        }
        return $_key;
    }

    /** *************************** Méthodes d'instance************************ */
    public function createActionCmd($cmdData, $path, $category) {
        /**
         * Crée une commande action
         *
         * @param $cmdData	array 	Tableau reçu contenant valeur, traduction...
         * @param $path			string	Chemin type de la commande
         * @param $category	array 	Catégorie de la commande
         * @return $cmd			object	Commande créée
         */
        $key = $cmdData['key'];
        if (!isset($cmdData['type']) || $cmdData['type'] == '') {
            $table = new homeconnect_capabilities();
            $tableData = $table->appliancesCapabilities;
            if (isset($tableData[$key])) {
                $cmdData = array_merge($cmdData, $tableData[$key]);
            }
        }
        log::add(__CLASS__, 'debug', __('Création d\'une commande action', __FILE__) . ', key : ' . $key . ', path : ' . $path . ', category : ' . $category);
        $logicalIdCmd = 'PUT::' . $key;
        if ($category == 'Program' && config::byKey('listValueProgramm', 'homeconnect', false)) {
            $logicalIdCmd = 'PUT::program';
        }
        $cmd = $this->getCmd(null, $logicalIdCmd);
        if (!is_object($cmd)) {
            // La commande n'existe pas, on la créée
            $cmd = new homeconnectCmd();
            $name = self::setCmdName($key, $cmdData);
            log::add(__CLASS__, 'debug', __('Nom de la nouvelle commande ', __FILE__) . $name);

            if ($this->cmdNameExists($name)) {
                $cmd->setName('Action ' . $name);
            } else {
                $cmd->setName($name);
            }
            $cmd->setLogicalId($logicalIdCmd);
            $cmd->setIsVisible(1);
            $cmd->setIsHistorized(0);
            // A voir en s'inspirant de homebridge homeconnect
            $cmd->setDisplay('generic_type', 'DONT');
            $cmd->setConfiguration('path', $path);
            $cmd->setConfiguration('key', $key);
            $cmd->setConfiguration('category', $category);
            $cmd->setEqLogic_id($this->getId());
            $cmd->setType('action');
            if ($cmdData['type'] == 'Int' || $cmdData['type'] == 'Double') {
                // commande slider.
                log::add(__CLASS__, 'debug', __('Nouvelle commande slider', __FILE__) . ', logicalId : ' . $logicalIdCmd . __(', nom : ', __FILE__) . $cmd->getName());
                $cmd->setSubType('slider');
                $cmd->setConfiguration('value', '#slider#');
                if (isset($cmdData['unit'])) {
                    $cmd->setConfiguration('unit', $cmdData['unit']);
                    if ($cmdData['unit'] == 'seconds') {
                        $cmd->setUnite('s');
                    } else {
                        $cmd->setUnite($cmdData['unit']);
                    }
                } else {
                    $cmd->setUnite('');
                }
                if (isset($cmdData['constraints']['min']) && isset($cmdData['constraints']['max'])) {
                    $cmd->setConfiguration('minValue', $cmdData['constraints']['min']);
                    $cmd->setConfiguration('maxValue', $cmdData['constraints']['max']);
                }
                log::add(__CLASS__, 'debug', 'Min = ' . $cmd->getConfiguration('minValue') . ', Max = ' . $cmd->getConfiguration('maxValue') . ', Unité = ' . $cmd->getUnite());
                if ($cmd->getConfiguration('maxValue') < 1000) {
                    $cmd->setTemplate('dashboard', 'button');
                    $cmd->setTemplate('mobile', 'button');
                } /*else {
                $cmd->setTemplate('dashboard', 'bigbutton');
                $cmd->setTemplate('mobile', 'bigbutton');
                }*/
                $arr = $cmd->getDisplay('parameters');
                if (!is_array($arr)) {
                    $arr = array();
                }
                if (isset($cmdData['constraints']['stepsize'])) {
                    $cmd->setConfiguration('step', $cmdData['constraints']['stepsize']);
                    $arr['step'] = $cmdData['constraints']['stepsize'];
                } else {
                    $$arr['step'] = 1;
                }
                /*if ($cmd->getConfiguration('maxValue') >= 1000) {
                $arr['bigstep'] = 900;
                }*/
                $cmd->setDisplay('parameters', $arr);
                $cmd->save();
            } else if (strpos($cmdData['type'], 'EnumType') !== false || $cmdData['type'] == 'Enumeration') {
                // Commande select
                log::add(__CLASS__, 'debug', __('Nouvelle commande select logicalId ', __FILE__) . $logicalIdCmd . __(', nom ', __FILE__) . $cmd->getName());
                $cmd->setSubType('select');
                $cmd->setConfiguration('value', '#select#');
                $optionValues = array();
                foreach ($cmdData['constraints']['allowedvalues'] as $optionValue) {
                    $optionValues[] = $optionValue . '|' . self::getCmdValueTranslation($key, $optionValue);
                }
                $listValue = implode(';', $optionValues);
                $cmd->setConfiguration('listValue', $listValue);
                $cmd->save();
            } else if ($key == 'BSH.Common.Setting.AmbientLightCustomColor') {
                // Commande color
                log::add(__CLASS__, 'debug', __('Nouvelle commande color logicalId ', __FILE__) . $logicalIdCmd . __(', nom ', __FILE__) . $cmd->getName());
                $cmd->setSubType('color');
                $cmd->setConfiguration('value', '#color#');
                $cmd->save();
            } elseif ($category == 'Program' && config::byKey('listValueProgramm', 'homeconnect', false)) {
                log::add(__CLASS__, 'debug', __('Nouvelle commande other Program logicalId ', __FILE__) . $logicalIdCmd . __(', nom ', __FILE__) . $cmd->getName());
                $cmd->setName('Action Programmes');
                $cmd->setSubType('select');
                $cmd->setConfiguration('value', '#select#');
                $listValue = $key . '|' . self::getCmdDetailTranslation($key, 'name');
                $cmd->setConfiguration('listValue', $listValue);
                $cmd->save();
            } else {
                log::add(__CLASS__, 'debug', __('Nouvelle commande other logicalId ', __FILE__) . $logicalIdCmd . __(', nom ', __FILE__) . $cmd->getName());
                $cmd->setSubType('other');
                if ($cmdData['type'] == 'Boolean') {
                    $cmd->setConfiguration('value', true);
                }
                $cmd->save();
            }
        } else {
           if ($category == 'Program' && $logicalIdCmd == 'PUT::program' && config::byKey('listValueProgramm', 'homeconnect', false)) {
                log::add(__CLASS__, 'debug', __('Mise à jour commande other Program logicalId ', __FILE__) . $logicalIdCmd . __(', nom ', __FILE__) . $cmd->getName());
                $elements = array_filter(explode(';', $cmd->getConfiguration('listValue', '')));
                $elements[] = $key . '|' . self::getCmdDetailTranslation($key, 'name');
                $elements = array_unique($elements);
                $listValue = implode(';', $elements);
                $cmd->setConfiguration('listValue', $listValue);
                $cmd->save();
           }
           log::add(__CLASS__, 'debug', __('La commande ', __FILE__) . $logicalIdCmd . __(' et nom ', __FILE__) . $cmd->getName() . __(' existe déjà', __FILE__));
        }
        return $cmd;
    }

    public function createInfoCmd($cmdData, $path, $category, $actionCmd = null) {
        /**
         * Crée une commande info
         *
         * @param $cmdData		array 	Tableau reçu contenant valeur, traduction...
         * @param $path				string	Chemin type de la commande
         * @param $category		array 	Catégorie de la commande
         * @param $actionCmd	object 	Commande action liée
         * @return $cmd				object	Commande info créée
         */
        $key = $cmdData['key'];
        if (!isset($cmdData['type']) || $cmdData['type'] == '') {
            $table = new homeconnect_capabilities();
            $tableData = $table->appliancesCapabilities;
            if (isset($tableData[$key])) {
                $cmdData = array_merge($cmdData, $tableData[$key]);
            }
        }
        log::add(__CLASS__, 'debug', __('Création d\'une commande info', __FILE__) . ', key : ' . $key . ', path : ' . $path . ', category : ' . $category);
        $logicalIdCmd = 'GET::' . $key;
        $cmd = $this->getCmd(null, $logicalIdCmd);
        if (!is_object($cmd)) {
            // La commande n'existe pas, on la créée
            $cmd = new homeconnectCmd();
            $name = self::setCmdName($key, $cmdData);
            log::add(__CLASS__, 'debug', __('Nom de la nouvelle commande ', __FILE__) . $name);

            if ($this->cmdNameExists($name)) {
                $cmd->setName('Info ' . $name);
            } else {
                $cmd->setName($name);
            }
            log::add(__CLASS__, 'debug', __('Nouvelle commande info ', __FILE__) . ', logicalId ' . $logicalIdCmd . __(' et nom ', __FILE__) . $cmd->getName() . __(' paramètres ', __FILE__) . json_encode($cmdData));
            $cmd->setLogicalId($logicalIdCmd);
            $cmd->setIsVisible(1);
            $cmd->setIsHistorized(0);
            // A voir en s'inspirant de homebridge homeconnect
            $cmd->setDisplay('generic_type', 'DONT');
            $cmd->setConfiguration('path', $path);
            $cmd->setConfiguration('key', $key);
            $cmd->setConfiguration('withAction', false);
            $cmd->setConfiguration('category', $category);
            $cmd->setEqLogic_id($this->getId());
            $cmd->setType('info');
            log::add(__CLASS__, 'debug', __('Type de création ', __FILE__) . 'isset(action) ' . isset($actionCmd) . ', isset(type) ' . isset($cmdData['type']) . ', isset(value) ' . isset($cmdData['value']));

            if (isset($actionCmd)) {
                // Il y aune commande action associée
                // On ne l'affiche pas
                $cmd->setIsVisible(0);
                $cmd->setConfiguration('withAction', true);
                // Détermination du subtype à partir de la commande action
                if ($actionCmd->getSubType() == 'slider') {
                    // commande numeric.
                    log::add(__CLASS__, 'debug', __('Création d\'une commande info numeric à partir de la commande action', __FILE__));
                    $cmd->setSubType('numeric');
                    $cmd->setConfiguration('minValue', $actionCmd->getConfiguration('minValue', 0));
                    $cmd->setConfiguration('maxValue', $actionCmd->getConfiguration('maxValue', 100));
                    $cmd->setUnite($actionCmd->getUnite());
                    log::add(__CLASS__, 'debug', "Min = " . $cmd->getConfiguration('minValue') . " Max = " . $cmd->getConfiguration('maxValue') . " Unité = " . $cmd->getUnite());
                    $cmd->save();
                } else if ($actionCmd->getSubType() == 'select') {
                    // Commande string
                    log::add(__CLASS__, 'debug', __('Création d\'une commande info string à partir de la commande action', __FILE__));
                    $cmd->setSubType('string');
                    $cmd->save();
                } else if ($actionCmd->getSubType() == 'color') {
                    // Commande color
                    log::add(__CLASS__, 'debug', __('Création d\'une commande info string à partir de la commande action', __FILE__));
                    $cmd->setSubType('string');
                    $cmd->save();
                } else if ($actionCmd->getSubType() == 'other') {
                    if ($actionCmd->getConfiguration('value') === true) {
                        // Commande binaire
                        log::add(__CLASS__, 'debug', __('Création d\'une commande info binary à partir de la commande action', __FILE__));
                        $cmd->setSubType('binary');
                    } else {
                        // Commande string
                        log::add(__CLASS__, 'debug', __('Création d\'une commande info other à partir de la commande action', __FILE__));
                        $cmd->setSubType('string');
                    }
                    $cmd->save();
                } else {
                    log::add(__CLASS__, 'debug', __('Problème avec le subtype de la commande action associée ', __FILE__) . $actionCmd->getSubType());
                }
                log::add(__CLASS__, 'debug', __('setValue sur la commande ', __FILE__) . $category . ', logicalId ' . $actionCmd->getLogicalId() . __(' commande info ', __FILE__) . $cmd->getLogicalId());
                $actionCmd->setValue($cmd->getId());
                $actionCmd->save();
            } else if (isset($cmdData['type'])) {
                // Determination du subType a l'aide de l'étiquette type
                if ($cmdData['type'] == 'Int' || $cmdData['type'] == 'Double') {
                    // commande numeric.
                    log::add(__CLASS__, 'debug', __('Création d\'une commande info numeric à partir de l\'étiquette type', __FILE__));
                    $cmd->setSubType('numeric');
                    if (isset($cmdData['unit'])) {
                        $cmd->setConfiguration('unit', $cmdData['unit']);
                        if ($cmdData['unit'] == 'seconds') {
                            $cmd->setUnite('s');
                        } else {
                            $cmd->setUnite($cmdData['unit']);
                        }

                    } else {
                        $cmd->setUnite('');
                    }
                    if (isset($cmdData['constraints']['min']) && isset($cmdData['constraints']['max'])) {
                        $cmd->setConfiguration('minValue', $cmdData['constraints']['min']);
                        $cmd->setConfiguration('maxValue', $cmdData['constraints']['max']);
                    }
                    log::add(__CLASS__, 'debug', 'Min = ' . $cmd->getConfiguration('minValue') . ', Max = ' . $cmd->getConfiguration('maxValue') . ', Unité = ' . $cmd->getUnite());
                    $cmd->save();
                } else if (strpos($cmdData['type'], 'EnumType') !== false || $cmdData['type'] == 'Enumeration') {
                    // Commande string
                    log::add(__CLASS__, 'debug', __('Création d\'une commande string à partir de l\'étiquette type', __FILE__));
                    $cmd->setSubType('string');
                    $cmd->save();
                } else if ($cmdData['type'] == 'Boolean') {
                    log::add(__CLASS__, 'debug', __('Création d\'une commande binary à partir de l\'étiquette type', __FILE__));
                    $cmd->setSubType('binary');
                    $cmd->save();
                }

            } else if (isset($cmdData['value'])) {
                // détermination du subtype à partir de value
                if ($cmdData['value'] === true || $cmdData['value'] === false) {
                    log::add(__CLASS__, 'debug', __('Création d\'une commande binary à partir de la value', __FILE__));
                    $cmd->setSubType('binary');
                    $cmd->save();
                } else if ($cmdData['value'] === null || strpos($cmdData['value'], 'EnumType') !== false) {
                    log::add(__CLASS__, 'debug', __('Création d\'une commande string à partir de la value', __FILE__));
                    $cmd->setSubType('string');
                    $cmd->save();
                } else if (is_numeric($cmdData['value'])) {
                    log::add(__CLASS__, 'debug', __('Création d\'une commande numeric à partir de la value', __FILE__));
                    $cmd->setSubType('numeric');
                    if (isset($cmdData['unit'])) {
                        $cmd->setConfiguration('unit', $cmdData['unit']);
                        if ($cmdData['unit'] == 'seconds') {
                            $cmd->setUnite('s');
                            $cmd->setConfiguration('minValue', 0);
                            $cmd->setConfiguration('maxValue', 86340);
                        } else {
                            $cmd->setUnite($cmdData['unit']);
                        }
                    } else {
                        $cmd->setUnite('');
                    }
                    $cmd->save();
                } else {
                    log::add(__CLASS__, 'debug', __('Impossible de trouver le subType à partir de value ', __FILE__) . print_r($cmdData, true));
                }
            } else {
                log::add(__CLASS__, 'debug', __('Impossible de trouver le subType ', __FILE__) . print_r($cmdData, true));
            }
        } else {
            log::add(__CLASS__, 'debug', __('La commande ', __FILE__) . $logicalIdCmd . __(' et nom ', __FILE__) . $cmd->getName() . __(' existe déjà', __FILE__));
        }
        return $cmd;
    }

    public function createProgramOption($path, $optionData) {
        /**
         * Crée le duet commande info et action avec le programme reçu
         *
         * @param $path					string	Chemin type de la commande
         * @param $optionData		array 	Tableau contenant les infos de la commande à créer
         * @return
         */
        if (isset($optionData['key'])) {
            if ($optionData['key'] !== 'BSH.Common.Option.StartInRelative') {
                $optionPath = $path . '/options/' . $optionData['key'];
            } else {
                // Cette option ne peut pas être utilisée avec selected uniquement avec active
                $optionPath = 'programs/active/options/' . $optionData['key'];
            }
            $actionCmd = $this->createActionCmd($optionData, $optionPath, 'Option');
            $infoCmd = $this->createInfoCmd($optionData, $optionPath, 'Option', $actionCmd);
            // le setValue est fait dans createInfoCmd

        } else {
            log::add(__CLASS__, 'debug', __('Clé manquante dans une option de programme', __FILE__));
        }
    }

    public function cmdNameExists($name) {
        /**
         * Vérifie si le nom de commande existe déjà
         *
         * @param $name	string	Nom de commande à vérifier
         * @return			bool	Renvoie 1 si existe
         */
        $cleanName = substr(cleanComponanteName($name) , 0, 127);
        foreach ($this->getCmd() as $liste_cmd) {
            if ($cleanName == $liste_cmd->getName()) {
                return true;
            }
        }
        return false;
    }

    public function getImage() {
        /**
         * Cherche et renvoie l'image en fonction du type d'appareil
         *
         * @return	$filename	string	Renvoie 1 si existe
         */
        $filename = 'plugins/homeconnect/core/config/images/' . $this->getConfiguration('type') . '.png';
        if (file_exists(__DIR__ . '/../../../../' . $filename)) {
            return $filename;
        }
        return 'plugins/homeconnect/plugin_info/homeconnect_icon.png';
    }

    public function applyModuleConfiguration($_remove = false) {
        /**
         * Applique le jeu de commande en fonction du type
         *
         * @param		$_remove bool	En supprimant les anciennes commandes ?
         * @return
         */
        log::add(__CLASS__, 'debug', __FUNCTION__ . __(' import de la configuration', __FILE__));

        $this->setConfiguration('applyType', $this->getConfiguration('type'));
        $this->save();
        if ($this->getConfiguration('type') == '') {
            return true;
        }
        $device = self::devicesParameters($this->getConfiguration('type'));
        if (!is_array($device)) {
            return true;
        }
        $this->import($device, $_remove);
    }

    public function isConnected() {
        /**
         * Renvoie l'état connecté de l'appareil
         * @return		bool	Vrai si connecté
         */
        $cmdConnected = $this->getCmd('info', 'connected');
        if (is_object($cmdConnected)) {
            if ($this->getIsEnable() && $cmdConnected->execCmd()) {
                return true;
            } else {
                return false;
            }
        } else {
            log::add(__CLASS__, 'debug', __('Erreur : La commande connected n\'existe pas', __FILE__));
            log::add(__CLASS__, 'debug', __('Type : ', __FILE__) . $this->getConfiguration('type', ''));
            log::add(__CLASS__, 'debug', __('Marque : ', __FILE__) . $this->getConfiguration('brand', ''));
            log::add(__CLASS__, 'debug', __('Modèle : ', __FILE__) . $this->getConfiguration('vib', ''));
            log::add(__CLASS__, 'debug', "Id : " . $this->getLogicalId());
        }
    }

    public function loadCmdFromConf($type) {
        /**
         * Charge le fichier de config des commandes à créer
         *
         * @param		$type		string		Type d'appareil
         * @return
         */
        log::add(__CLASS__, 'debug', __('Début ', __FILE__) . __FUNCTION__ . ' : ' . $type);
        if (!is_file(dirname(__FILE__) . '/../config/types/' . $type . '.json')) {
            log::add(__CLASS__, 'debug', __('Fichier introuvable ', __FILE__) . $type);
            return;
        }
        $content = file_get_contents(dirname(__FILE__) . '/../config/types/' . $type . '.json');
        if (!is_json($content)) {
            log::add(__CLASS__, 'debug', __('Pas un json ', __FILE__) . $type);
            return;
        }
        $device = json_decode($content, true);
        if (!is_array($device) || !isset($device['commands'])) {
            log::add(__CLASS__, 'debug', __('Pas un tableau ou aucune commande ', __FILE__) . $type);
            return true;
        }
        foreach ($device['commands'] as $command) {
            $cmd = null;
            foreach ($this->getCmd() as $liste_cmd) {
                if ((isset($command['logicalId']) && $liste_cmd->getLogicalId() == $command['logicalId']) || (isset($command['name']) && $liste_cmd->getName() == $command['name'])) {
                    $cmd = $liste_cmd;
                    break;
                }
            }
            if ($cmd == null || !is_object($cmd)) {
                $cmd = new homeconnectCmd();
                $cmd->setEqLogic_id($this->getId());
                utils::a2o($cmd, $command);
                $cmd->save();
            }
        }
        event::add('jeedom::alert', array(
            'level' => 'warning',
            'page' => 'homeconnect',
            'message' => '',
        ));
        log::add(__CLASS__, 'debug', __('Fin ', __FILE__) . __FUNCTION__);
    }

    public function adjustProgramOptions($typeProgram, $programKey) {
        /**
         * Récupère et attribue des paramètres aux commandes existantes
         *
         * @param		$typeProgram	string		Type de programme (inutile)
         * @param		$programKey		string		Clé du programme
         * @return
         */
        // Cette fonction est appelée quand il y a eu un changement de programme (actif ou sélectionné) et ajuste les options en fonction de ce programme
        log::add(__CLASS__, 'debug', __('Appel de la fonction adjustProgramOptions pour le type de programme ', __FILE__) . $typeProgram . __(', clé ', __FILE__) . $programKey);
        $programdata = self::request(self::API_REQUEST_URL . '/' . $this->getLogicalId() . '/programs/available/' . $programKey, null, 'GET', array());
        log::add(__CLASS__, 'debug', __('Résultat de la requête ', __FILE__) . $programdata);
        $programdata = json_decode($programdata, true);
        if (isset($programdata['data']['options'])) {
            $opt = array();
            $cmdProgram = $this->getCmd('action', 'PUT::' . $programKey);
            foreach ($programdata['data']['options'] as $optionData) {
                if (isset($optionData['key'])) {
                    $key = $optionData['key'];
                    array_push($opt, $key);
                    // Commande option action
                    $logicalIdCmd = 'PUT::' . $key;
                    log::add(__CLASS__, 'debug', __('Ajustement de la commande action ', __FILE__) . $logicalIdCmd);
                    $cmd = $this->getCmd('action', $logicalIdCmd);
                    if (is_object($cmd)) {
                        if ($cmd->getSubType() == 'slider') {
                            // commande slider.
                            log::add(__CLASS__, 'debug', __('Ajustement commande action slider', __FILE__) . ', logicalId ' . $logicalIdCmd . __(', nom ', __FILE__) . $cmd->getName());
                            if (isset($optionData['unit'])) {
                                $cmd->setConfiguration('unit', $optionData['unit']);
                                if ($optionData['unit'] == 'seconds') {
                                    $cmd->setUnite('s');
                                } else {
                                    $cmd->setUnite($optionData['unit']);
                                }

                            } else {
                                $cmd->setUnite('');
                            }
                            if (isset($optionData['constraints']['min']) && isset($optionData['constraints']['max'])) {
                                $cmd->setConfiguration('minValue', $optionData['constraints']['min']);
                                $cmd->setConfiguration('maxValue', $optionData['constraints']['max']);
                            }
                            log::add(__CLASS__, 'debug', 'Min = ' . $cmd->getConfiguration('minValue') . ', Max = ' . $cmd->getConfiguration('maxValue') . ', Unité = ' . $cmd->getUnite());
                            $arr = $cmd->getDisplay('parameters');
                            if (!is_array($arr)) {
                                $arr = array();
                            }
                            if (isset($optionData['constraints']['stepsize'])) {
                                $cmd->setConfiguration('step', $optionData['constraints']['stepsize']);
                                $arr['step'] = $optionData['constraints']['stepsize'];
                            } else {
                                $$arr['step'] = 1;
                            }
                            /*if ($cmd->getConfiguration('maxValue') >= 1000) {
                            $arr['bigstep'] = 900;
                            }*/
                            $cmd->setDisplay('parameters', $arr);
                            $cmd->save();
                        } else if ($cmd->getSubType() == 'select') {
                            // Commande select
                            log::add(__CLASS__, 'debug', __('Ajustement commande action select', __FILE__) . ', logicalId ' . $logicalIdCmd . __(', nom ', __FILE__) . $cmd->getName());
                            $optionValues = array();
                            foreach ($optionData['constraints']['allowedvalues'] as $optionValue) {
                                $optionValues[] = $optionValue . '|' . self::getCmdValueTranslation($key, $optionValue);
                            }
                            $listValue = implode(';', $optionValues);
                            log::add(__CLASS__, 'debug', "listValue " . $listValue);
                            $cmd->setConfiguration('listValue', $listValue);
                            $cmd->save();
                        } else {
                            log::add(__CLASS__, 'debug', __('Commande action other rien à ajuster ', __FILE__) . $logicalIdCmd . __(', nom ', __FILE__) . $cmd->getName() . ' subtype ' . $cmd->getSubType());
                        }
                    } else {
                        $pathCreate = 'programs/selected';
                        if (is_object($cmdProgram)) {
                            $pathCreate = $cmdProgram->getConfiguration('path', $pathCreate);
                        }
                        $cmdActionOption = $this->getCmd('action', 'PUT::' . $optionData['key']);
                        $cmdInfoOption = $this->getCmd('info', 'GET::' . $optionData['key']);
                        if (!is_object($cmdActionOption) && !is_object($cmdInfoOption)) {
                            log::add(__CLASS__, 'debug', __('Commandes options action et info inexistantes PUT::/GET::', __FILE__) . $optionData['key']);
                            $this->createProgramOption($pathCreate, $optionData);
                        }
                        log::add(__CLASS__, 'debug', __('La commande action ', __FILE__) . $logicalIdCmd . __(' n\'existe pas impossible de l\'ajuster', __FILE__));
                    }
                    // commande option info
                    $logicalIdCmd = 'GET::' . $key;
                    log::add(__CLASS__, 'debug', __('Ajustement de la commande info ', __FILE__) . $logicalIdCmd);
                    $cmd = $this->getCmd('info', $logicalIdCmd);
                    if (is_object($cmd)) {
                        if ($cmd->getSubType() == 'numeric') {
                            // commande numeric.
                            log::add(__CLASS__, 'debug', __('Ajustement commande info numeric logicalId ', __FILE__) . $logicalIdCmd . __(', nom ', __FILE__) . $cmd->getName());
                            if (isset($optionData['unit'])) {
                                $cmd->setConfiguration('unit', $optionData['unit']);
                                if ($optionData['unit'] == 'seconds') {
                                    $cmd->setUnite('s');
                                } else {
                                    $cmd->setUnite($optionData['unit']);
                                }
                            } else {
                                $cmd->setUnite('');
                            }
                            if (isset($optionData['constraints']['min']) && isset($optionData['constraints']['max'])) {
                                $cmd->setConfiguration('minValue', $optionData['constraints']['min']);
                                $cmd->setConfiguration('maxValue', $optionData['constraints']['max']);
                            }
                            log::add(__CLASS__, 'debug', 'Min = ' . $cmd->getConfiguration('minValue') . ', Max = ' . $cmd->getConfiguration('maxValue') . ', Unité = ' . $cmd->getUnite());
                            $cmd->save();
                        } else {
                            // Dans les autres cas il n'y a rien à faire.
                            log::add(__CLASS__, 'debug', __('Rien à ajuster pour une commande info de subType ', __FILE__) . $cmd->getSubType());
                        }
                    } else {
                        $this->updateInfoCmdValue($logicalIdCmd, $optionData);
                        log::add(__CLASS__, 'debug', __('La commande info ', __FILE__) . $logicalIdCmd . __(' n\'existe pas impossible de l\'ajuster', __FILE__));
                    }
                } else {
                    log::add(__CLASS__, 'debug', __('Pas de key dans optionData', __FILE__));
                }
            }
            if (is_object($cmdProgram)) {
                $configOpt = array_merge($opt, $cmdProgram->getConfiguration('listOptions', array()));
                $configOpt = array_unique($configOpt);
                $cmdProgram->setConfiguration('listOptions', $configOpt)->save();
                log::add(__CLASS__, 'debug', __('Ajout des options disponibles dans la commande PUT::$programKey', __FILE__) . print_r($configOpt, true));
            }
        } else {
            log::add(__CLASS__, 'debug', __('Pas d\'options à ajuster', __FILE__));
        }
    }

    public function updateInfoCmdValue($logicalId, $value) {
        /**
         * Met à jour la valeur de la commande
         *
         * @param		$logicalId	string		LogicalId de la commande
         * @param		$value			string		Valeur à mettre à jour
         * @return
         */
        $parts = explode('::', $logicalId);
        $cmd = $this->getCmd('info', $logicalId);
        $reglage = '';
        if (is_object($cmd)) {
            if (is_bool($value['value'])) {
                $value['value'] = $value['value'] ? 'true' : 'false';
            }
            if ($cmd->getConfiguration('withAction')) {
                // C'est une commande associée à une commande action pas de traduction
                if (isset($value['value'])) {
                    $reglage = $value['value'];
                } else {
                    log::add(__CLASS__, 'debug', __('La commande info ', __FILE__) . $logicalId . __(' n\'a pas de valeur', __FILE__));
                }
            } else {
                if (isset($value['value'])) {
                    if ($cmd->getSubType() == 'string') {
                        $reglage = self::getCmdValueTranslation($parts[1], $value['value']);
                    } else {
                        $reglage = $value['value'];
                    }
                } else {
                    log::add(__CLASS__, 'debug', __('La commande info ', __FILE__) . $logicalId . __(' n\'a pas de valeur', __FILE__));
                }
            }
            $this->checkAndUpdateCmd($cmd, $reglage);
            log::add(__CLASS__, 'debug', __('Mise à jour setting ', __FILE__) . $logicalId . __(', valeur ', __FILE__) . $reglage);
        } else {
            log::add(__CLASS__, 'debug', __('Dans updateInfoCmdValue la commande ', __FILE__) . $logicalId . __(' n\'existe pas', __FILE__));
        }
    }

    public function lookProgram($programType) {
        /**
         * Questionnement du programme pour avoir ses infos
         *
         * @param		$programType	string		Si actif ou selectionné
         * @return  $key	string		Renvoi la clé du programme si pas d'erreur
         */
        if ($programType == 'Selected') {
            $nameCmd = 'GET::BSH.Common.Root.SelectedProgram';
        } else {
            $nameCmd = 'GET::BSH.Common.Root.ActiveProgram';
        }
        $currentProgram = self::request(self::API_REQUEST_URL . '/' . $this->getLogicalId() . '/programs/' . strtolower($programType) , null, 'GET', array());
        if ($currentProgram !== false) {
            log::add(__CLASS__, 'debug', __FUNCTION__ . __(' Réponse pour program ', __FILE__) . $programType . __('dans lookProgram ', __FILE__) . $currentProgram);
            $currentProgram = json_decode($currentProgram, true);
            if (isset($currentProgram['data']['key']) && $currentProgram['data']['key'] !== 'SDK.Error.NoProgram' . $programType) {
                $key = $currentProgram['data']['key'];
                log::add(__CLASS__, 'debug', __FUNCTION__ . 'Program ' . $programType . ', key ' . $key);
                // recherche du programme action associé
                $actionCmd = $this->getCmd('action', 'PUT::' . $key);
                if (!is_object($actionCmd)) {
                    log::add(__CLASS__, 'debug', __FUNCTION__ . __(' Nouveau program ', __FILE__) . $programType . ', key ' . $key);
                    $this->lookProgramAvailable($programType, $currentProgram['data']);
                    log::add(__CLASS__, 'debug', __FUNCTION__ . __(' Pas de commande action ', __FILE__) . 'PUT::' . $key);
                    $programName = self::getCmdDetailTranslation($key, 'name');
                } else {
                    $programName = $actionCmd->getName();
                    log::add(__CLASS__, 'debug', __FUNCTION__ . __(' Nom de la commande action ', __FILE__) . $programName);
                }
                // MAJ de la commande info ProgramSelected ou ProgramActive.
                $cmd = $this->getCmd('info', $nameCmd);
                if (is_object($cmd)) {
                    log::add(__CLASS__, 'debug', __('Mise à jour de la valeur de la commande action ', __FILE__) . $nameCmd . ' : ' . $programName);
                    $this->checkAndUpdateCmd($cmd, $programName);
                    return $key;
                } else {
                    log::add(__CLASS__, 'debug', __('La commande ', __FILE__) . $nameCmd . __(' n\'existe pas', __FILE__));
                }
                //recherche des options ce program pour ajout cmd option
                //$this->lookProgramOptions($programType, $key); // déjà fait ?

            } else {
                // Pas de programme actif
                // A voir : mettre à jour les autres commandes (états et réglages)
                log::add(__CLASS__, 'debug', __('Pas de key ou key = SDK.Error.NoProgram ', __FILE__) . $programType);
                $this->checkAndUpdateCmd($nameCmd, __('Aucun', __FILE__));
            }
        } else {
            log::add(__CLASS__, 'debug', __('Dans lookProgram request a retourné faux', __FILE__));
        }
        return false;
    }

    public function lookProgramAvailable($programType, $applianceProgram) {
        /**
         * Questionnement du programme disponible pour savoir s'il est disponible
         *
         * @param		$programType	string		Si actif ou selectionné
         * @param		$applianceProgram	array
         * @return
         */
        $programdata = self::request(self::API_REQUEST_URL . '/' . $this->getLogicalId() . '/programs/available/' . $applianceProgram['key'], null, 'GET', array());
        log::add(__CLASS__, 'debug', 'Appliance Program available' . print_r($programdata, true));
        if ($programdata !== false && $programdata !== 'SDK.Error.UnsupportedProgram') {
            $programdata = json_decode($programdata, true);

            if (isset($programdata['data']['key'])) {
                $actionCmd = $this->createActionCmd($programdata['data'], 'programs/' . strtolower($programType), 'Program');
                if ($programType == 'Selected' || $programType == 'Active') {
                    $infoCmd = $this->getCmd('info', 'GET::BSH.Common.Root.' . $programType . 'Program');
                    if (is_object($infoCmd)) {
                        // On a trouvé la commande info associée.
                        log::add(__CLASS__, 'debug', __FUNCTION__ . __('setValue sur la commande programme ', __FILE__) .$programType . ' ' . $actionCmd->getLogicalId() . __(' commande info ', __FILE__) . $infoCmd->getLogicalId());
                        $actionCmd->setValue($infoCmd->getId());
                        $actionCmd->save();
                    } else {
                        log::add(__CLASS__, 'debug', __FUNCTION__ . __('Pas de commande info GET::BSH.Common.Root.', __FILE__) . $programType . 'Program');
                    }
                }
            }
        }
    }

    public function lookProgramOptions($programType, $_key) {
        /**
         * Questionnement du programme disponible pour avoir ses options
         *
         * @param		$programType	string		Si actif ou selectionné
         * @param		$_key	string		 Clé du programme
         * @return
         */
        $programOptions = self::request(self::API_REQUEST_URL . '/' . $this->getLogicalId() . '/programs/' . strtolower($programType) . '/options', null, 'GET', array());
        if ($programOptions !== false) {
            $programOptions = json_decode($programOptions, true);
            if (isset($programOptions['data']['key']) && $programOptions['data']['key'] !== 'SDK.Error.UnsupportedProgram') {
                log::add(__CLASS__, 'debug', 'options : ' . $programOptions);
                // MAJ des options et autres informations du programme en cours.
                $opt = array();
                $cmdProgram = $this->getCmd('action', 'PUT::' . $_key);

                foreach ($programOptions['data']['options'] as $value) {
                    array_push($opt, $value['key']);
                    log::add(__CLASS__, 'debug', 'option : ' . print_r($value, true));
                    $cmdActionOption = $this->getCmd('action', 'PUT::' . $value['key']);
                    $cmdInfoOption = $this->getCmd('info', 'GET::' . $value['key']);
                    if (!is_object($cmdActionOption) && !is_object($cmdInfoOption)) {
                        log::add(__CLASS__, 'debug', __('Commandes options action et info inexistantes PUT::/GET::', __FILE__) . $value['key']);
                        $this->createProgramOption('programs/' . strtolower($programType) , $value);
                    }
                    //$this->createInfoCmd($value, $optionPath, 'Option');
                    $this->updateInfoCmdValue($value['key'], $value);
                }
                if (is_object($cmdProgram)) {
                    $configOpt = array_merge($opt, $cmdProgram->getConfiguration('listOptions', array()));
                    $configOpt = array_unique($configOpt);
                    $cmdProgram->setConfiguration('listOptions', $configOpt)->save();
                    log::add(__CLASS__, 'debug', __('Ajout des options disponibles dans la commande PUT::', __FILE__). $programKey . ' ' . print_r($configOpt, true));
                }
            }
        }
    }

    public function updateProgram() {
        /**
         * Mise à jour du programme et recherche des options
         *
         * @return
         */
        if ($this->isConnected()) {
            $eqLogicType = $this->getConfiguration('type');
            if ($eqLogicType == 'Refrigerator' || $eqLogicType == 'FridgeFreezer' || $eqLogicType == 'WineCooler' || !$this->getConfiguration('hasPrograms', true)) {
                log::add(__CLASS__, 'debug', __('Pas de programme pour ce type d\'appareil', __FILE__));
                return;
            }
            log::add(__CLASS__, 'debug', "MAJ du programme actif");
            $activeProgram = $this->lookProgram('Active');
            if ($activeProgram) {
                // Il y a un programme actif on regarde ses options
                log::add(__CLASS__, 'debug', __('Il y a un programme actif', __FILE__));
                $this->lookProgramOptions('Active', $activeProgram);
            } else {
                // Pas de programme actif on essaie le programme sélectionné
                $selectedProgram = $this->lookProgram('Selected');
                if ($selectedProgram) {
                    log::add(__CLASS__, 'debug', __('Il y a un programme sélectionné', __FILE__));
                    $this->lookProgramOptions('Selected', $selectedProgram);
                }
            }
            if (!$activeProgram && !$selectedProgram) {
                cache::set('homeconnect::startinrelative::' . $this->getId() , '', '');
            }
        }
    }

    public function updateStates() {
        /**
         * Mise à jour des états
         *
         * @return
         */
        if ($this->isConnected()) {
            log::add(__CLASS__, 'debug', __('MAJ des états ', __FILE__) . $this->getLogicalId());

            $response = self::request(self::API_REQUEST_URL . '/' . $this->getLogicalId() . '/status', null, 'GET', array());
            log::add(__CLASS__, 'debug', "Réponse dans updateStates " . $response);
            if ($response !== false) {
                $response = json_decode($response, true);
                foreach ($response['data']['status'] as $value) {
                    log::add(__CLASS__, 'debug', 'status : ' . print_r($value, true));
                    // Récupération du logicalId du status.
                    $logicalId = 'GET::' . $value['key'];
                    $cmd = $this->getCmd('info', $logicalId);
                    if (!is_object($cmd)) {
                        $this->createInfoCmd($value, 'status/' . $value['key'], 'Status');
                    }
                    $this->updateInfoCmdValue($logicalId, $value);
                }
            }
        } else {
            log::add(__CLASS__, 'debug', __('Non connecté, pas de mise à jour des états', __FILE__));
        }
    }

    public function updateSettings() {
        /**
         * Mise à jour des settings
         *
         * @return
         */
        if ($this->isConnected()) {
            log::add(__CLASS__, 'debug', __('MAJ des réglages ', __FILE__) . $this->getLogicalId());

            $response = self::request(self::API_REQUEST_URL . '/' . $this->getLogicalId() . '/settings', null, 'GET', array());
            log::add(__CLASS__, 'debug', __('Réponse updateSettings ', __FILE__) . $response);
            if ($response !== false) {
                $response = json_decode($response, true);
                foreach ($response['data']['settings'] as $value) {
                    log::add(__CLASS__, 'debug', 'setting : ' . print_r($value, true));
                    // Récupération du logicalId du setting.
                    $logicalId = 'GET::' . $value['key'];
                    $cmd = $this->getCmd('info', $logicalId);
                    if (!is_object($cmd)) {
                        $this->createInfoCmd($value, 'settings/' . $value['key'], 'Setting');
                    }
                    $this->updateInfoCmdValue($logicalId, $value);
                }
            }
        } else {
            log::add(__CLASS__, 'debug', __('Non connecté, pas de mise à jour des états', __FILE__));
        }
    }

    public function updateApplianceData() {
        /**
         * Mise à jour des infos de l'appareil
         *
         * @return
         */
        log::add(__CLASS__, 'debug', __('Début ', __FILE__) . __FUNCTION__);
        if ($this->getIsEnable()) {
            log::add(__CLASS__, 'debug', __('Mise à jour du status connecté', __FILE__));
            $response = self::request(self::API_REQUEST_URL, null, 'GET', array());
            $response = json_decode($response, true);
            foreach ($response['data']['homeappliances'] as $appliance) {
                log::add(__CLASS__, 'debug', __('Appareil ', __FILE__) . print_r($appliance, true));
                if ($this->getLogicalId() == $appliance['haId']) {
                    $cmd = $this->getCmd('info', 'connected');
                    if (is_object($cmd)) {
                        log::add(__CLASS__, 'debug', __('Mise à jour commande connectée valeur ', __FILE__) . $appliance['connected']);
                        $this->checkAndUpdateCmd($cmd, $appliance['connected']);
                    }
                }
            }
            $this->updateProgram();
            $this->updateStates();
            $this->updateSettings();
            $this->refreshWidget();
        }
        log::add(__CLASS__, 'debug', __('Fin ', __FILE__) . __FUNCTION__);
    }

    public function postSave() {
        /**
         * Création / MAJ des commandes des appareils.
         *
         * @param			|*Cette fonction ne retourne pas de valeur*|
         * @return			|*Cette fonction ne retourne pas de valeur*|
         */
        log::add(__CLASS__, 'debug', __('Début ', __FILE__) . __FUNCTION__);

        if ($this->getConfiguration('applyType') != $this->getConfiguration('type')) {
            $this->applyModuleConfiguration();
            //A voir : Supprimer toutes les commandes ici
            $this->refreshWidget();
        }
        //Parce qu'elles sont de toute façon mises à jour ici.
        $this->loadCmdFromConf($this->getConfiguration('type'));
        log::add(__CLASS__, 'debug', __('Fin ', __FILE__) . __FUNCTION__);
    }

}

class homeconnectCmd extends cmd {

    public function execute($_options = array()) {
        // Bien penser dans les fichiers json à mettre dans la configuration
        // key, value, type, constraints et à modifier findProduct
        log::add('homeconnnect', 'debug', __('Début ', __FILE__) . __FUNCTION__);
        homeconnect::verifyToken(60);

        if ($this->getType() == 'info') {
            log::add('homeconnect', 'debug', __('Pas d\'execute pour une commande info', __FILE__));
            return;
        }
        $eqLogic = $this->getEqLogic();
        $haid = $eqLogic->getConfiguration('haid', '');
        log::add('homeconnect', 'debug', "logicalId : " . $this->getLogicalId());
        log::add('homeconnect', 'debug', "Options : " . print_r($_options, true));

        if ($this->getLogicalId() == 'DELETE::StopActiveProgram') {
            // Commande Arrêter
            log::add('homeconnect', 'debug', __('Commande arrêter', __FILE__));
            // Si l'appareil n'a pas de programme on ne peut pas arrêter
            if (!$eqLogic->getConfiguration('hasPrograms', true)) {
                log::add('homeconnect', 'debug', __('L\'appareil n\'a pas de programmes impossible d\'arrêter', __FILE__));
                return;
            }
            // S'il n'y a pas de programme actif on ne peut pas arrêter
            $response = homeconnect::request(homeconnect::API_REQUEST_URL . '/' . $haid . '/programs/active', null, 'GET', array());
            if ($response == false || $response == 'SDK.Error.NoProgramActive') {
                log::add('homeconnect', 'debug', __('Pas de programme actif impossible d\'arrêter', __FILE__));
                return;
            }
        }
        // Pour la commande arrêter le traitement continue
        if ($this->getLogicalId() == 'start') {
            // Commande Lancer
            log::add('homeconnect', 'debug', __('Commande lancer', __FILE__));
            // Si l'appareil n'a pas de programme on ne peut pas lancer
            if (!$eqLogic->getConfiguration('hasPrograms', true)) {
                log::add('homeconnect', 'debug', __('L\'appareil n\'a pas de programmes, impossible de lancer', __FILE__));
                return;
            }

            // On lance le programme sélectionné à condition qu'il existe
            log::add('homeconnect', 'debug', __('Recherche du programme sélectionné', __FILE__));
            $response = homeconnect::request(homeconnect::API_REQUEST_URL . '/' . $haid . '/programs/selected', null, 'GET', array());
            log::add('homeconnect', 'debug', __('Réponse du serveur pour le programme sélectionné ', __FILE__) . $response);
            if ($response == false) {
                log::add('homeconnect', 'debug', __('Pas de programme sélectionné impossible de lancer', __FILE__));
                event::add('jeedom::alert', array(
                    'level' => 'warning',
                    'message' => __('Sélectionnez un programme avant de lancer', __FILE__) ,
                ));
                return;
            }
            $decodedResponse = json_decode($response, true);
            if (!isset($decodedResponse['data']['key'])) {
                log::add('homeconnect', 'debug', __('Pas de programme dans la réponse impossible de lancer', __FILE__));
                return;
            }
            $key = $decodedResponse['data']['key'];
            $selectedProgramCmd = $eqLogic->getCmd(null, 'PUT::' . $key);
            if (!is_object($selectedProgramCmd)) {
                // Commande pour le programme sélectionné non trouvée
                log::add('homeconnect', 'debug', __('La commande logicalId ', __FILE__) . 'PUT::' . $key . __(' n\'existe pas impossible de lancer', __FILE__));
                return;
            }
            // Si ce n'est pas un programme selectandstart impossible de lancer
            if ($selectedProgramCmd->getConfiguration('path', '') !== 'programs/selected') {
                log::add('homeconnect', 'debug', __('Le programme sélectionné n\'est pas select and start, impossible de lancer', __FILE__));
                return;
            }
            $url = homeconnect::API_REQUEST_URL . '/' . $haid . '/programs/active';
            $payload = '{"data": {"key": "' . $key . '"';

            // Il faut récupérer la valeur du départ différé et la mettre dans le payload.
            $cache = cache::byKey('homeconnect::startinrelative::' . $eqLogic->getId());
            $startinrelative = $cache->getValue();
            if ($startinrelative !== '' && $startinrelative !== 0) {
                $payload .= ',"options": [' . $startinrelative . ']';
            }
            $payload .= '}}';
            log::add('homeconnect', 'debug', __('Url pour le lancement ', __FILE__) . $url);
            log::add('homeconnect', 'debug', __('Payload pour le lancement ', __FILE__) . $payload);
            $result = homeconnect::request($url, $payload, 'PUT', array());
            log::add('homeconnect', 'debug', __('Réponse du serveur au lancement ', __FILE__) . $result);
            $eqLogic->updateApplianceData();
            return;

        }
        if ($this->getLogicalId() == 'refresh') {
            log::add('homeconnect', 'debug', __('| Commande refresh', __FILE__));
            $eqLogic->updateApplianceData();
            return;
        }
        log::add('homeconnect', 'debug', "| Commande générique");
        $parts = explode('::', $this->getLogicalId());
        if (count($parts) !== 2) {
            log::add('homeconnect', 'debug', __('Le logicalId de la commande contient trop de parties', __FILE__));
            return;
        }
        $method = $parts[0];
        $key = $parts[1];
        // A voir : faut il ajouter qqchose aux headers par defaut de request
        $headers = array();

        // Bien penser à mettre la partie après haid de l'url dans configuration path de la commande
        $path = $this->getConfiguration('path', '');
        $replace = array();
        switch ($this->getSubType()) {
            case 'slider':
                $replace['#slider#'] = intval($_options['slider']);
            break;
            case 'color':
                $replace['#color#'] = $_options['color'];
            break;
            case 'select':
                $replace['#select#'] = $_options['select'];
            break;
            case 'message':
                $replace['#title#'] = $_options['title'];
                $replace['#message#'] = $_options['message'];
                if ($_options['message'] == '' && $_options['title'] == '') {
                    throw new Exception(__('Le message et le sujet ne peuvent pas être vide', __FILE__));
                }
            break;
        }

        if ($method == 'DELETE') {
            $payload = null;
        }
        if ($this->getLogicalId() !== 'PUT::BSH.Common.Option.StartInRelative') {
            // La commande départ différé doit être envoyée au moment du lancer de programme.
            $parameters = array(
                'data' => array()
            );
            if ($this->getConfiguration('key') !== '') {
                $parameters['data']['key'] = $this->getConfiguration('key', '');
            }
            if ($this->getConfiguration('value') !== '') {
                if (is_bool($this->getConfiguration('value'))) {
                    if ($this->getValue() != '') {
                        $cmdValue = cmd::byId($this->getValue());
                        if (is_object($cmdValue)) {
                            $parameters['data']['value'] = !$cmdValue->execCmd();
                        }
                    } else {
                        $parameters['data']['value'] = $this->getConfiguration('value');
                    }
                } else {
                    $parameters['data']['value'] = str_replace(array_keys($replace) , $replace, $this->getConfiguration('value', ''));
                }
            }
            if ($this->getConfiguration('unit', '') !== '') {
                $parameters['data']['unit'] = $this->getConfiguration('unit', '');
            }
            if ($this->getConfiguration('type', '') !== '') {
                $parameters['data']['type'] = $this->getConfiguration('type', '');
            }
            $payload = json_encode($parameters, JSON_NUMERIC_CHECK);

            $url = homeconnect::API_REQUEST_URL . '/' . $haid . '/' . $path;
            log::add('homeconnect', 'debug', __('Paramètres de la requête pour exécuter la commande ', __FILE__));
            log::add('homeconnect', 'debug', 'Method : ' . $method);
            log::add('homeconnect', 'debug', 'Url : ' . $url);
            log::add('homeconnect', 'debug', 'Payload : ' . $payload);
            $response = homeconnect::request($url, $payload, $method, $headers);
            log::add('homeconnect', 'debug', __('Réponse du serveur ', __FILE__) . $response);
            // si la requête est de category program il faut mettre à jour les options
            if ($this->getConfiguration('category') == 'Program') {
                $typeProgram = homeconnect::lastSegment('/', $url);
                $eqLogic->adjustProgramOptions($typeProgram, $this->getConfiguration('key'));
                // A voir dans ce cas ce qu'il faut mettre à jour.
            }
            $eqLogic->updateApplianceData();
        } else {
            $value = str_replace(array_keys($replace) , $replace, $this->getConfiguration('value', ''));
            if ($value !== '' && $value !== 0) {
                $parameters = array(
                    'key' => 'BSH.Common.Option.StartInRelative',
                    'value' => $value,
                    'unit' => 'seconds'
                );
                $payload = json_encode($parameters, JSON_NUMERIC_CHECK);
                //$payload = '{"key":"BSH.Common.Option.StartInRelative","value":' . $value. ',"unit":"seconds"}';
                cache::set('homeconnect::startinrelative::' . $eqLogic->getId() , $payload, '');
                // il faut mémoriser la valeur du départ différé.
            }
        }
    }
}
?>
