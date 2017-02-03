<?

require_once(__DIR__ . "/../cloudtrax.php");
require_once(__DIR__ . "/../logging.php");

define('IPS_BASE', 10000);   
define('IPS_KERNELMESSAGE', IPS_BASE + 100);           //Kernel Message
define('KR_CREATE', IPS_KERNELMESSAGE + 1);            //Kernel is beeing created
define('KR_INIT', IPS_KERNELMESSAGE + 2);              //Kernel Components are beeing initialised, Modules loaded, Settings read
define('KR_READY', IPS_KERNELMESSAGE + 3);             //Kernel is ready and running
define('KR_UNINIT', IPS_KERNELMESSAGE + 4);            //Got Shutdown Message, unloading all stuff
define('KR_SHUTDOWN', IPS_KERNELMESSAGE + 5);

class CloudTraxNetworkModule extends IPSModule {

   public function Create(){
        parent::Create();
        
        $this->RegisterPropertyBoolean ("Log", false );
		
		$this->RegisterPropertyString("key", "");
		$this->RegisterPropertyString("secret", "");
		
		$this->RegisterPropertyInteger("network", 0);
		
   }
   
   public function ApplyChanges(){
        parent::ApplyChanges();

		$log = new CTLogging($this->ReadPropertyBoolean("Log"), IPS_Getname($this->InstanceID));
		
		$key = $this->ReadPropertyString('key');
		$secret = $this->ReadPropertyString('secret');
		
		if(strlen($key)==0 || strlen($secret)==0) {
			$log->LogMessage('Missing Key or Secret. Aborting ApplyChanges()');
			return;
		}
		
		$log->LogMessage('Read Key and Secret');
		
		$ctc = new CloudTraxCommunication($key, $secret);
		$ctc->ConfigureLogging($this->ReadPropertyBoolean("Log"), IPS_Getname($this->InstanceID));

		if(strlen($this->GetBuffer($this->InstanceID.'networks'))==0) {
			$ctns = new CloudTraxNetworks ($ctc);
			$ctns->Refresh();
			$networks = $ctns->GetNetworks();
			if($networks)
				$log->LogMessage('Retrieved all networks: '. print_r($networks, true));
			else {
				echo "Failed to retrieve networks. Check log for details";
				$log->LogMessage('Unable to retrieve networks');
				return false;
			}
			$this->SetBuffer($this->InstanceID.'networks', json_encode($networks, true));	
		} else
			$log->LogMessage('Available networks are already retrieved');
		
		$selectedNetwork = $this->ReadPropertyString('network');
		if($selectedNetwork>0 && strlen($this->GetBuffer($this->InstanceID.'ssids'))==0){
			$ctn = new CloudTraxNetwork($ctc, $selectedNetwork);
			$ctn->Refresh();
			$ssids = $ctn->GetSSIDs();
			if($ssids)
				$log->LogMessage('Retrieved all ssids: '. print_r($ssids, true));
			else
				$log->LogMessage('Unable to retrieve ssids');
			
			$this->SetBuffer($this->InstanceID.'ssids', json_encode($ssids, true));
		} elseif($selectedNetwork==0)
			$this->SetBuffer($this->InstanceID.'ssids', '');
		elseif(strlen($this->GetBuffer($this->InstanceID.'ssids'))>0)
			$log->LogMessage('Available ssids are already retrieved');
					
		//$this->RegisterMessage(0, IPS_KERNELMESSAGE);
		
		return true;
		
    }
	
	public function CreateNetwork(string $Name, string $Password, string $Timezone, string $CountryCode){
		$log = new CTLogging($this->ReadPropertyBoolean("Log"), IPS_Getname($this->InstanceID));
		
		$key = $this->ReadPropertyString('key');
		$secret = $this->ReadPropertyString('secret');
		
		if(strlen($key)==0 || strlen($secret)==0) {
			$log->LogMessage('Missing Key or Secret. Aborting CreateNetwork()');
			return false;
		}
		
		$ctc = new CloudTraxCommunication($key, $secret);
		$ctc->ConfigureLogging($this->ReadPropertyBoolean("Log"), IPS_Getname($this->InstanceID));
		$ctns = new CloudTraxNetworks ($ctc);
		
		if($ctns->CreateNetwork($Name, $Password, $Timezone, $CountryCode)) {
			$networks = $ctns->GetNetworks();
			$this->SetBuffer($this->InstanceID.'networks', json_encode($networks, true));
		} else {
			$Log->LogMessage('Failed to create the new network!');
			return false;
		}
		
		return true;
		
	}
	
	public function EnableSSID(string $SSID, bool $Enable) {
		$log = new CTLogging($this->ReadPropertyBoolean("Log"), IPS_Getname($this->InstanceID));
		
		$key = $this->ReadPropertyString('key');
		$secret = $this->ReadPropertyString('secret');
		
		if(strlen($key)==0 || strlen($secret)==0) {
			$log->LogMessage('Misisng Key or Secret. Aborting EnableSSID()');
			return false;
		}
				
		$networkId = $this->ReadPropertyInteger('network');
		if($networkId==0) {
			$log->LogMessage('The network is not selected. Aborting EnableSSID()');
			return false;
		}
					
		$ctc = new CloudTraxCommunication($key, $secret);
		$ctc->ConfigureLogging($this->ReadPropertyBoolean("Log"), IPS_Getname($this->InstanceID));
		$ctn = new CloudTraxNetwork($ctc, $networkId);
		
		$ssids = $this->GetBuffer($this->InstanceID.'ssids');
		if(strlen($ssids)>0)
			$ctn->SetSSIDs(json_decode(ssids, true));
		else
			$ctn->Refresh();
		
		
		$result = $ctn->EnableSSID($SSID, $Enable);
		if($result) {
			$log->LogMessage('EnableSSID() succeeded');
			return true;
		} else {
			$log->LogMessage('EnableSSID() failed');
			return false;
		}
			
	}
	
	public function EnableHidden(string $SSID, bool $Enable) {
		$log = new CTLogging($this->ReadPropertyBoolean("Log"), IPS_Getname($this->InstanceID));
		
		$key = $this->ReadPropertyString('key');
		$secret = $this->ReadPropertyString('secret');
		
		if(strlen($key)==0 || strlen($secret)==0) {
			$log->LogMessage('Misisng Key or Secret. Aborting EnableHidden()');
			return false;
		}
				
		$networkId = $this->ReadPropertyInteger('network');
		if($networkId==0) {
			$log->LogMessage('The network is not selected. Aborting EnableHidden()');
			return false;
		}
		
		$ctc = new CloudTraxCommunication($key, $secret);
		$ctc->ConfigureLogging($this->ReadPropertyBoolean("Log"), IPS_Getname($this->InstanceID));
		$ctn = new CloudTraxNetwork($ctc, $networkId);
		
		$ssids = $this->GetBuffer($this->InstanceID.'ssids');
		if(strlen($ssids)>0)
			$ctn->SetSSIDs(json_decode($ssids, true));
		else
			$ctn->Refresh();
		
		$result = $ctn->EnableHidden($SSID, $Enable);
		if($result) {
			$log->LogMessage('EnableHidden() succeeded');
			return true;
		} else {
			$log->LogMessage('EnableHidden() failed');
			return false;
		}	
	
	}

	public function SetBridgedWiredClients(string $SSID) {
		$log = new CTLogging($this->ReadPropertyBoolean("Log"), IPS_Getname($this->InstanceID));
		
		$key = $this->ReadPropertyString('key');
		$secret = $this->ReadPropertyString('secret');
		
		if(strlen($key)==0 || strlen($secret)==0) {
			$log->LogMessage('Misisng Key or Secret. Aborting SetBridgedWiredClients()');
			return false;
		}
				
		$networkId = $this->ReadPropertyInteger('network');
		if($networkId==0) {
			$log->LogMessage('The network is not selected. Aborting SetBridgedWiredClients()');
			return false;
		}
			
		$ctc = new CloudTraxCommunication($key, $secret);
		$ctc->ConfigureLogging($this->ReadPropertyBoolean("Log"), IPS_Getname($this->InstanceID));
		$ctn = new CloudTraxNetwork($ctc, $networkId);
		
		$ssids = $this->GetBuffer($this->InstanceID.'ssids');
		if(strlen($ssids)>0)
			$ctn->SetSSIDs(json_decode($ssids, true));
		else
			$ctn->Refresh();
		
		$result = $ctn->SetBridgedWiredClients($SSID);
		if($result) {
			$log->LogMessage('SetBridgedWiredClients() succeeded');
			return true;
		} else {
			$log->LogMessage('SetBridgedWiredClients() failed');
			return false;
		}
	
	}
	
	public function RefreshCloudTrax() {
			$this->SetBuffer($this->InstanceID.'ssids','');
			$this->SetBuffer($this->InstanceID.'networks','');
			if($this->ApplyChanges())
				return "Please reload the configuration form to show updated information!";
			
	}
   
	public function GetConfigurationForm(){
		$log = new CTLogging($this->ReadPropertyBoolean("Log"), IPS_Getname($this->InstanceID));
		
		$log->LogMessage('Generating configuration form');
		
		$networksJSON = $this->GetBuffer($this->InstanceID.'networks');
	   
		if(strlen($networksJSON) > 0){
			$log->LogMessage('Creating drop down box for available networks');
			$options = '{ "type": "Select", "name": "network", "caption": "Network",
								"options": [';
								
			$option = '{ "label": "No network selected", "value": 0 },';
			$options .= $option;
			$networks = json_decode($networksJSON, true);
			foreach($networks as $network) {
				$name = $network['name'];
				$id = $network['id'];
				$option = '{ "label": "'.$name.'", "value": '.$id.' },';
				$options .= $option;
			}

			$options .= '					]
							},';
			$ssidInfo = '{ "type": "Label", "label": "Select network and press Apply to see available SSIDs!" },';
		} else {
			$log->LogMessage('There is no network(s) retrieved from CloudTrax');
			$options = '{ "type": "Label", "label": "Register API Authentication information and press Apply!" },';
			$ssidInfo = '{ "type": "Label", "label": "" },';
		}		
			   
		$ssidsJSON = $this->GetBuffer($this->InstanceID.'ssids') ;
		//$ssidInfo = '{ "type": "Label", "label": "Select network and press Apply to see available SSIDs!" },';
		if(strlen($ssidsJSON) > 0){
			$log->LogMessage('Creating list of available SSIDs');
			$ssids = json_decode($ssidsJSON, true);
			$ssidList = '';
			foreach($ssids as $ssid) {
				$name = $ssid['name'];
				$ssidList.= strlen($ssidList)==0?$name:', '.$name;
			}
				
			$ssidInfo = '{ "type": "Label", "label": "Available SSIDs: '.$ssidList.'" }, 
						 {"type": "Button", "label": "Refresh", "onClick": "echo CTN_RefreshCloudTrax($id);"},';
		} else
			$log->LogMessage('There is no SSIDs retrieved from CloudTrax');
		
		$form = '{"elements":
						[
							{ "type": "Label", "label": "API Authentication:" },
							{ "name": "key", "type": "ValidationTextBox", "caption": "Key:" },
							{ "name": "secret", "type": "ValidationTextBox", "caption": "Secret:" },
							{ "type": "Label", "label": "Selected network:" },'.$options.$ssidInfo.
							'{ "type": "Label", "label": "Other settings:" },
							{ "type": "CheckBox", "name": "Log", "caption": "Enable logging:" }
						],
						}';

		return $form;

	}
	
	public function MessageSink($TimeStamp, $SenderID, $Message, $Data) {
		switch ($Message) {
			case IPS_KERNELMESSAGE:
				switch ($Data[0]){
					case KR_READY:
						//IPS_LogMessage('CloudTrax', 'Kernel ready!');
						break;
					
				}
				break;
		}	

	}
		
}

?>
