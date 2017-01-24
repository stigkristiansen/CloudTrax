<?

require_once(__DIR__ . "/../logging.php");
require_once(__DIR__ . "/../cloudtrax.php");

class CloudTraxNetworkModule extends IPSModule {

   public function Create(){
        parent::Create();
        
        $this->RegisterPropertyBoolean ("Log", false );
		
		$this->RegisterPropertyString("key", "");
		$this->RegisterPropertyString("secret", "");
		
		$this->RegisterPropertyInteger("network", 0);
		
   }
   
   public function GetConfigurationForm(){

		$networks = $this->GetBuffer('networks');
	   
		if(sizeof($networks) > 0){
			$options = '{ "type": "Select", "name": "network", "caption": "Network",
								"options": [';
									//{ "label": "Click Refresh Networks", "value": 0 },
									//{ "label": "BM123", "value": 12345 },
									//{ "label": "HS67", "value": 54321 }
			$option .= '					]
							},';
		} else
			$options = '{ "type": "Label", "label": "Register API Authentication information and press Apply!" },';
						
		IPS_LogMessage('CloudTrax',"GetConfigForm - Got buffer: ".$this->GetBuffer('networks'));
	   
		$form = '{"elements":
						[
							{ "type": "Label", "label": "API Authentication" },
							{ "name": "key", "type": "ValidationTextBox", "caption": "Key:" },
							{ "name": "secret", "type": "ValidationTextBox", "caption": "Secret:" },
							{ "type": "Select", "name": "network", "caption": "Network",
								"options": [
									{ "label": "Click Refresh Networks", "value": 0 },
									{ "label": "BM123", "value": 12345 },
									{ "label": "HS67", "value": 54321 }
								]
							},
							{ "type": "Label", "label": "Other settings" },
							{ "type": "CheckBox", "name": "Log", "caption": "Enable logging:" }
						],
						}';

		return $form;
   }

    public function ApplyChanges(){
        parent::ApplyChanges();
		
		$key = $this->ReadPropertyString('key');
		if(strlen($key)==0)
			return;
		
		$secret = $this->ReadPropertyString('secret');
		if(strlen($secret)==0)
			return;
		
				
		$selectedNetwork = $this->ReadPropertyString('network');
		
		$ctc = new CloudTraxCommunication($key, $secret);
		
		//$networkId = $ctns->GetNetworkIdByName('bm123');
		
		if($selectedNetwork==0) {
			$ctns = new CloudTraxNetworks ($ctc);
			$networks = $ctns->GetNetworks();
			$this->SetBuffer('networks', json_encode($networks, true));
			
		} 
		
		IPS_LogMessage('CloudTrax',"Apply - Setbuffer to: ".$this->GetBuffer('networks'));
			
		
		
		
		
    }

		
	private function Lock($Ident) {
        $log = new Logging($this->ReadPropertyBoolean("Log"), IPS_Getname($this->InstanceID));
		for ($x=0;$x<200;$x++)
        {
            if (IPS_SemaphoreEnter("GH_".(string)$this->InstanceID.(string)$Ident, 1)){
                return true;
            }
            else {
  				if($x==0)
					$log->LogMessage("Waiting for controller to unlock...");
				IPS_Sleep(50);
            }
        }
        return false;
    }

    private function Unlock($Ident) {
        IPS_SemaphoreLeave("GH_".(string)$this->InstanceID.(string)$Ident);
		$log = new Logging($this->ReadPropertyBoolean("Log"), IPS_Getname($this->InstanceID));
		$log->LogMessage("The controller is unlocked");
    }
		
}

?>
