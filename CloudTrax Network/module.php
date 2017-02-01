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
		if(strlen($key)==0)
			return;
		
		$secret = $this->ReadPropertyString('secret');
		if(strlen($secret)==0)
			return;

		$log->LogMessage('Read Key and Secret');
		
		$ctc = new CloudTraxCommunication($key, $secret);
		$ctc->ConfigureLogging($this->ReadPropertyBoolean("Log"), IPS_Getname($this->InstanceID));

		if(strlen($this->GetBuffer($this->InstanceID.'networks'))==0) {
			$ctns = new CloudTraxNetworks ($ctc);
			$ctns->Refresh();
			$networks = $ctns->GetNetworks();
			if($networks)
				$log->LogMessage('Retrieved all networks: '. print_r($networks, true));
			else
				$log->LogMessage('Unable to retrieve networks');
			
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
		
    }
	
	public function EnableSSID(string $SSID, bool $Enable) {
		$key = $this->ReadPropertyString('key');
		if(strlen($key)==0)
			return false;
		
		$secret = $this->ReadPropertyString('secret');
		if(strlen($secret)==0)
			return false;
		
		$networkId = $this->ReadPropertyInteger('network');
		if($networkId==0)
			return false;
			
		$ctc = new CloudTraxCommunication($key, $secret);
		$ctc->ConfigureLogging($this->ReadPropertyBoolean("Log"), IPS_Getname($this->InstanceID));
		$ctn = new CloudTraxNetwork($ctc, $networkId);
		
		$ssids = $this->GetBuffer($this->InstanceID.'ssids');
		if(strlen($ssids)>0)
			$ctn->SetSSIDs(json_decode(ssids, true));
		else
			$ctn->Refresh();
				
		return $ctn->EnableSSID($SSID, $Enable);
			
	}
	
	public function EnableHidden(string $SSID, bool $Enable) {
		$key = $this->ReadPropertyString('key');
		if(strlen($key)==0)
			return false;
		
		$secret = $this->ReadPropertyString('secret');
		if(strlen($secret)==0)
			return false;
		
		$networkId = $this->ReadPropertyInteger('network');
		if($networkId==0)
			return false;
				
		$ctc = new CloudTraxCommunication($key, $secret);
		$ctc->ConfigureLogging($this->ReadPropertyBoolean("Log"), IPS_Getname($this->InstanceID));
		$ctn = new CloudTraxNetwork($ctc, $networkId);
		
		$ssids = $this->GetBuffer($this->InstanceID.'ssids');
		if(strlen($ssids)>0)
			$ctn->SetSSIDs(json_decode($ssids, true));
		else
			$ctn->Refresh();
		
		return $ctn->EnableHidden($SSID, $Enable);
			
	}


	public function SetBridgedWiredClients(string $SSID) {
		$key = $this->ReadPropertyString('key');
		if(strlen($key)==0)
			return false;
		
		$secret = $this->ReadPropertyString('secret');
		if(strlen($secret)==0)
			return false;
		
		$networkId = $this->ReadPropertyInteger('network');
		if($networkId==0)
			return false;
			
		$ctc = new CloudTraxCommunication($key, $secret);
		$ctc->ConfigureLogging($this->ReadPropertyBoolean("Log"), IPS_Getname($this->InstanceID));
		$ctn = new CloudTraxNetwork($ctc, $networkId);
		
		$ssids = $this->GetBuffer($this->InstanceID.'ssids');
		if(strlen($ssids)>0)
			$ctn->SetSSIDs(json_decode($ssids, true));
		else
			$ctn->Refresh();
		
		return $ctn->SetBridgedWiredClients($SSID);
	
	}
   
	public function GetConfigurationForm(){

		$networksJSON = $this->GetBuffer($this->InstanceID.'networks');
	   
		if(strlen($networksJSON) > 0){
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
		} else
			$options = '{ "type": "Label", "label": "Register API Authentication information and press Apply!" },';
						
		//IPS_LogMessage('CloudTrax',"GetConfigForm - Got buffer: ".$this->GetBuffer($this->InstanceID.'networks'));
	   
		$ssidsJSON = $this->GetBuffer($this->InstanceID.'ssids') ;
		$ssidInfo = '{ "type": "Label", "label": "Select network and press Apply to see available SSIDs!" },';
		if(strlen($ssidsJSON) > 0){
			$ssids = json_decode($ssidsJSON, true);
			$ssidList = '';
			foreach($ssids as $ssid) {
				$name = $ssid['name'];
				$ssidList.= strlen($ssidList)==0?$name:', '.$name;
			}
				
			$ssidInfo = '{ "type": "Label", "label": "Available SSIDs: '.$ssidList.'" },';
		}
		
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
