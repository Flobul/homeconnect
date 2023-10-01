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


if (!isConnect('admin')) {
    throw new Exception('{{401 - Accès non autorisé}}');
}
$table = new homeconnect_capabilities();
$tableData = $table->appliancesCapabilities;
sendVarToJS('cmdsParam', $tableData);
if (init('eqLogic_id') == '') {
    throw new Exception('{{L\'id de l\'équipement ne peut etre vide : }}' . init('eqLogic_id'));
}
$eqLogic = eqLogic::byId(init('eqLogic_id'));
if (!is_object($eqLogic)) {
    throw new Exception('{{Aucun équipement associé à l\'id : }}' . init('eqLogic_id'));
}

?>
<div role="tabpanel">
  <div class="tab-content" id="div_displayCmdConfigure" style="overflow-x:hidden">
  <div class="input-group pull-right" style="display:inline-flex">
    <span class="input-group-btn">
      </a><a class="btn btn-success btn-sm roundedRight roundedLeft" id="bt_cmdCreateSave"><i class="fas fa-check-circle"></i> {{Sauvegarder}}</a>
    </span>
  </div>
    <div role="tabpanel" class="tab-pane active" id="cmd_information">
      <br/>
      <div class="row">
        <div class="col-sm-9" >
          <form class="form-horizontal">
            <fieldset>
              <div class="form-group">
                <div class="col-xs-9">
                  <select id="sel_object" class="eqLogicAttr form-control" data-l1key="object_id">
                    <option value="">{{Aucun}}</option>
                      <?php
                          $lastKey = '';
                          foreach ($tableData as $capability => $parameters) {
                              if (isset($parameters['available'])) {
                                  if (in_array($eqLogic->getConfiguration('type'), $parameters['available'])) {
                                      $options = '';
                                      if ($parameters['action'] == 'Program') {
                                          if ($lastKey !== $parameters['action']) {
                                              $options .= '<optgroup label="- [ ' . $parameters['action'] . ' ] -" id="group"></optgroup>';
                                          }
                                          $options .= '<option value="' . $capability . '">Programme > ' . $parameters['name'] . str_repeat('&nbsp;', 40 - strlen($parameters['name'])) . ' > '. $capability . '</option>';
                                          $lastKey = $parameters['action'];
                                      }
                                      echo $options;
                                  }
                              }
                          }
                          //not sur if action command
                          /*
                          foreach ($tableData as $capability => $parameters) {
                              if (isset($parameters['available'])) {
                                  if (in_array($eqLogic->getConfiguration('type'), $parameters['available'])) {
                                      $options = '';
                                      if ($parameters['action'] == 'Option') {
                                          if ($lastKey !== $parameters['action']) {
                                              $options .= '<optgroup label="- [ ' . $parameters['action'] . ' ] -" id="group"></optgroup>';
                                          }
                                          $options .= '<option value="' . $capability . '">' . $parameters['name'] . str_repeat('&nbsp;', 40 - strlen($parameters['name'])). ' > ' . $capability . '</option>';
                                          $lastKey = $parameters['action'];
                                      }
                                      echo $options;
                                  }
                              }
                          }*/
                          //not action command
                          /*foreach ($tableData as $capability => $parameters) {
                              if (isset($parameters['available'])) {
                                  //foreach ()
                                  if (in_array($eqLogic->getConfiguration('type'), $parameters['available'])) {
                                      $options = '';
                                      if ($parameters['action'] == 'Status') {
                                          if ($lastKey !== $parameters['action']) {
                                              $options .= '<optgroup label="- [ ' . $parameters['action'] . ' ] -" id="group"></optgroup>';
                                          }
                                          $options .= '<option value="' . $capability . '">' . $parameters['name'] . str_repeat('&nbsp;', 40 - strlen($parameters['name'])). ' > ' . $capability . ')</option>';
                                          $lastKey = $parameters['action'];
                                      }
                                      echo $options;
                                  }
                              }
                          }*/
                          foreach ($tableData as $capability => $parameters) {
                              if (isset($parameters['available'])) {
                                  if (in_array($eqLogic->getConfiguration('type'), $parameters['available'])) {
                                      $options = '';
                                      if ($parameters['action'] == 'Setting') {
                                          if ($lastKey !== $parameters['action']) {
                                              $options .= '<optgroup label="- [ ' . $parameters['action'] . ' ] -" id="group"></optgroup>';
                                          }
                                          $options .= '<option value="' . $capability . '">' . $parameters['name'] . str_repeat('&nbsp;', 40 - strlen($parameters['name'])). ' > ' . $capability . '</option>';
                                          $lastKey = $parameters['action'];
                                      }
                                      echo $options;
                                  }
                              }
                          }
                          //not action command
                          /*foreach ($tableData as $capability => $parameters) {
                              if (isset($parameters['available'])) {
                                  if (in_array($eqLogic->getConfiguration('type'), $parameters['available'])) {
                                      $options = '';
                                      if ($parameters['action'] == 'Event') {
                                          if ($lastKey !== $parameters['action']) {
                                              $options .= '<optgroup label="- [ ' . $parameters['action'] . ' ] -" id="group"></optgroup>';
                                          }
                                          $options .= '<option value="' . $capability . '">' . $parameters['name'] . str_repeat('&nbsp;', 40 - strlen($parameters['name'])). ' > ' . $capability . ')</option>';
                                          $lastKey = $parameters['action'];
                                      }
                                      echo $options;
                                  }
                              }

                          }*/
                      ?>
				  </select>
                </div>
              </div>
            </fieldset>
          </form>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
console.log(cmdsParam['BSH.Common.Setting.TemperatureUnit']['enum'].length)

  for (const [key, value] of Object.entries(cmdsParam['BSH.Common.Setting.TemperatureUnit']['enum'])) {
  console.log(value);
}


$('#bt_cmdCreateSave').off().on('click',function() {
	var cle = $("#cmd_information #sel_object option:selected").value();
    console.log('cle',cle)
      console.log('zetzet',cmdsParam[cle]['name'])

	if(cle == '' || !cmdsParam[cle]){
          $('#div_alert').showAlert({message: '{{Veuillez sélectionnez une commande}}', level: 'danger'});
    } else {
        var path = '';
        if (cmdsParam[cle]['action'] == 'Program') {
            path = 'programs/active';
        } else if (cmdsParam[cle]['action'] == 'Setting') {
            path = 'settings/' + cle;
        } else if (cmdsParam[cle]['action'] == 'Status') {
            path = 'status/' + cle;
        }  else if (cmdsParam[cle]['action'] == 'Option') {
            path = 'status/' + cle;
        }
        var subType = 'other';
        var listValue = '';
        if (cmdsParam[cle]['type'] == 'Enumeration') {
            subType = 'select';
            for (const [key, value] of Object.entries(cmdsParam[cle]['enum'])) {
                listValue += key + '|' + value.name + ';';
            }
            listValue.substring(0,listValue.length-1);
        }
		var cmdData = {
			name: cmdsParam[cle]['name'],
			type: 'action',
			subType: subType,
			logicalId: 'PUT::' + cle,
			isVisible: 1,
			configuration: {
				"path": path,
				"key": cle,
				"category": cmdsParam[cle]['action'],
				...(listValue != '') && {"listValue": listValue, "value": "#select#"}
			}
 	     };
		addCmdToTable(cmdData);
        modifyWithoutSave = true
        $('#md_modal').dialog('close');
		$('#div_alert').showAlert({message: '{{Commande créée avec succès ! Cliquez sur Sauvegarder pour enregistrer la commande.}}', level: 'success'});
    }
});
</script>
