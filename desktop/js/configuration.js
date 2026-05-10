

// Utilitaire AJAX vanilla JS
function homeconnectAjax(data, successCallback, errorCallback) {
    var formData = new FormData();
    for (var key in data) {
        formData.append(key, data[key]);
    }
    fetch('plugins/homeconnect/core/ajax/homeconnect.ajax.php', {
        method: 'POST',
        body: formData
    })
    .then(function(response) { return response.json(); })
    .then(function(json) { if (successCallback) successCallback(json); })
    .catch(function(error) { if (errorCallback) errorCallback(error); });
}


// ── Délégation d'événements sur le formulaire de configuration ──────────────
var divPluginConfiguration = document.getElementById('configuration_plugin_homeconnect');
if (divPluginConfiguration) {
    divPluginConfiguration.addEventListener('change', function(event) {
        var target = event.target;
        if (_target = event.target.closest('.configKey[data-l1key=demo_mode]')) {
            if (_target.checked) {
                document.getElementById('bt_loginDemoHomeConnect').style.display = 'inline-block';
                document.getElementById('bt_loginHomeConnect').style.display = 'none';
            } else {
                document.getElementById('bt_loginDemoHomeConnect').style.display = 'none';
                document.getElementById('bt_loginHomeConnect').style.display = 'inline-block';
            }     
        }
    });
    divPluginConfiguration.addEventListener('click', function(event) {
        var _target = null;

        if (_target = event.target.closest('#bt_loginHomeConnect, #bt_loginDemoHomeConnect')) {
            _target.disabled = true;
            _target.innerHTML = '<i class="fas fa-spinner fa-spin"></i> {{Connexion en cours...}}';

            homeconnectAjax(
                { action: 'loginHomeConnect' },
                function(data) {
                    _target.disabled = false;
                    _target.innerHTML = '<i class="fas fa-fingerprint"></i> {{Se connecter}}';

                    console.log('[HomeConnect] Réponse loginHomeConnect :', data);

                    if (!data || data.result === false) {
                        jeedomUtils.showAlert({
                            message: '{{Erreur lors de la connexion, veuillez vérifier vos identifiant et mot de passe.}}',
                            level: 'danger'
                        });
                        return;
                    }
                    if (data.result && data.result.token) {
                        jeedomUtils.showAlert({
                            message: '<i class="fas fa-check-circle"></i> {{Connexion au compte HomeConnect réussie.}}' +
                                     '<br><small>{{Identifiant compte}} : <strong>' + (data.result.accountID || '') + '</strong></small>',
                            level: 'success'
                        });
			            window.location.href = data.result.redirect;
                        return;
                    }
                    jeedomUtils.showAlert({
                        message: '{{Erreur lors de la connexion}} : ' + (data.result && data.result.message ? data.result.message : '{{erreur inconnue}}'),
                        level: 'danger'
                    });
                },
                function(error) {
                    _target.disabled = false;
                    _target.innerHTML = '<i class="fas fa-fingerprint"></i> {{Se connecter}}';
                    console.error('[HomeConnect] Erreur AJAX :', error);
                    jeedomUtils.showAlert({
                        message: '{{Erreur de communication avec le serveur.}}',
                        level: 'danger'
                    });
                }
            );
        }     
        if (_target = event.target.closest('#bt_savePluginLogConfig')) {      
            var plugin = document.getElementById('span_plugin_id').textContent;
            var logPluginLevel = document.getElementById('div_plugin_log').getValues('.configKey')[0];
            var logPluginLeveltoStr = JSON.stringify(logPluginLevel);
            document.querySelectorAll('.bt_plugin_conf_view_log').forEach(function(element) {
                var filename = element.getAttribute('data-log');
                logPluginLeveltoStr = logPluginLeveltoStr.replace("log::level::" + plugin, "log::level::" + filename);
                newLogPluginLevel = JSON.parse(logPluginLeveltoStr);
                jeedom.config.save({
                    configuration: newLogPluginLevel,
                    error: function(error) {
                        jeedomUtils.showAlert({
                            message: error.message,
                            level: 'danger'
                        })
                    },
                    success: function() {
                        jeedomUtils.showAlert({
                            message: '{{Sauvegarde de la configuration des logs}} <i>' + filename + '</i> {{effectuée}}',
                            level: 'success'
                        })
                        modifyWithoutSave = false
                    }
                });
            });
        }
        if (_target = event.target.closest('#redirectUriHomeconnect')) {      
            _target.select(); //is this js vanilla?
            document.execCommand('copy');
            jeedomUtils.showAlert({
                message: '{{Redirect URI copiée dans le presse-papier}}',
                level: 'success'
            });
        }
    });
}

// ── Suivi des modifications non sauvegardées (pattern SmartThings) ──────────
function printPluginConfiguration() {
    var divPluginLGConfiguration = document.getElementById('configuration_plugin_homeconnect');
    var btnSavePluginConfig = document.getElementById('bt_savePluginConfig');
    if (!divPluginLGConfiguration || !btnSavePluginConfig) return;

    var configInputs    = divPluginLGConfiguration.querySelectorAll('.configKey');
    var modificationCount = 0;
    var initialValues   = new Map();

    var modificationMessage = document.createElement('i');
    modificationMessage.classList.add('modificationWithoutSave', 'label', 'label-warning', 'pull-right');
    modificationMessage.innerHTML = '{{Modification en cours...}}';
    modificationMessage.unseen();
    btnSavePluginConfig.parentNode.insertBefore(modificationMessage, btnSavePluginConfig.nextSibling);

    function resetStyle(element) {
        element.style.setProperty('background-color', '', 'important');
        element.style.setProperty('color', '', 'important');
    }

    function setModifiedStyle(element) {
        element.style.setProperty('background-color', 'var(--al-warning-color)', 'important');
        element.style.setProperty('color', 'var(--sc-lightTxt-color)', 'important');
    }

    function updateModificationStatus() {
        if (modificationCount > 0) {
            modificationMessage.seen();
        } else {
            modificationMessage.unseen();
        }
    }

    configInputs.forEach(function(input) {
        resetStyle(input);
        if (input.type === 'checkbox') {
            initialValues.set(input, input.checked);
        } else {
            initialValues.set(input, input.value);
        }
    });

    configInputs.forEach(function(input) {
        if (input.type === 'checkbox') {
            input.addEventListener('change', function() {
                var initialValue = initialValues.get(this);
                var isModified   = this.checked !== initialValue;
                if (isModified && !this.hasAttribute('data-modified')) {
                    setModifiedStyle(this);
                    this.setAttribute('data-modified', '');
                    modificationCount++;
                } else if (!isModified && this.hasAttribute('data-modified')) {
                    resetStyle(this);
                    this.removeAttribute('data-modified');
                    modificationCount--;
                }
                updateModificationStatus();
            });
        } else {
            var eventType = input.nodeName === 'SELECT' ? 'change' : 'input';
            input.addEventListener(eventType, function() {
                var initialValue = initialValues.get(this);
                var isModified   = this.value !== initialValue;
                if (isModified && !this.hasAttribute('data-modified')) {
                    setModifiedStyle(this);
                    this.setAttribute('data-modified', '');
                    modificationCount++;
                } else if (!isModified && this.hasAttribute('data-modified')) {
                    resetStyle(this);
                    this.removeAttribute('data-modified');
                    modificationCount--;
                }
                updateModificationStatus();
            });
        }
    });

    btnSavePluginConfig.addEventListener('click', function() {
        configInputs.forEach(function(input) {
            if (input.type === 'checkbox') {
                initialValues.set(input, input.checked);
            } else {
                initialValues.set(input, input.value);
            }
            resetStyle(input);
            input.removeAttribute('data-modified');
        });
        modificationCount = 0;
        modificationMessage.unseen();
    });

    if (document.querySelector('#configuration_plugin_homeconnect #redirectUriHomeconnect').value.length > 128) {
        document.querySelector('#configuration_plugin_homeconnect #textRedirectUriHomeconnect').classList.add('text-danger');
    } else {
        document.querySelector('#configuration_plugin_homeconnect #textRedirectUriHomeconnect').classList.remove('text-danger');
    }
}

// ── Initialisation ───────────────────────────────────────────────────────────
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', printPluginConfiguration);
} else {
    setTimeout(printPluginConfiguration, 100);
}

// ── Bouton "Donner mon avis" ─────────────────────────────────────────────────
var btRefresh = document.querySelector('.bt_refreshPluginInfo');
if (btRefresh) {
    btRefresh.insertAdjacentHTML('afterend',
        '<a class="btn btn-success btn-sm" target="_blank" href="https://market.jeedom.com/index.php?v=d&p=market_display&id=3894">' +
        '<i class="fas fa-comment-dots"></i> {{Donner mon avis}}</a>'
    );
}