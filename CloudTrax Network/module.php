<?

require_once(__DIR__ . "/../logging.php");
require_once(__DIR__ . "/../cloudtrax.php");


class CloudTraxNetworkModule extends IPSModule {
	define('IPS_KERNELMESSAGE', IPS_BASE + 100);           //Kernel Message
	define('KR_CREATE', IPS_KERNELMESSAGE + 1);            //Kernel is beeing created
	define('KR_INIT', IPS_KERNELMESSAGE + 2);              //Kernel Components are beeing initialised, Modules loaded, Settings read
	define('KR_READY', IPS_KERNELMESSAGE + 3);             //Kernel is ready and running
	define('KR_UNINIT', IPS_KERNELMESSAGE + 4);            //Got Shutdown Message, unloading all stuff
	define('KR_SHUTDOWN', IPS_KERNELMESSAGE + 5);  

   public function Create(){
        parent::Create();
        
        $this->RegisterPropertyBoolean ("Log", false );
		
		$this->RegisterPropertyString("key", "");
		$this->RegisterPropertyString("secret", "");
		
		$this->RegisterPropertyInteger("network", 0);
		
   }
   
   public function GetConfigurationForm(){

		$networksJSON = $this->GetBuffer($this->InstanceID.'networks') ;
	   
		if(strlen($networksJSON) > 0){
			$options = '{ "type": "Select", "name": "network", "caption": "Network",
								"options": [';
								
			$option = '{ "label": "Select a network", "value": 0 },';
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
						
		IPS_LogMessage('CloudTrax',"GetConfigForm - Got buffer: ".$this->GetBuffer($this->InstanceID.'networks'));
	   
		$form = '{"elements":
						[
							{ "type": "Label", "label": "API Authentication" },
							{ "name": "key", "type": "ValidationTextBox", "caption": "Key:" },
							{ "name": "secret", "type": "ValidationTextBox", "caption": "Secret:" },'.$options.
							'{ "type": "Label", "label": "Other settings" },
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
		
				
		//$selectedNetwork = $this->ReadPropertyString('network');
		
		$ctc = new CloudTraxCommunication($key, $secret);
		
		// Remember to make the buffer name uniqe		
		if(strlen($this->GetBuffer($this->InstanceID.'networks'))==0) {
			$ctns = new CloudTraxNetworks ($ctc);
			$networks = $ctns->GetNetworks();
			$this->SetBuffer($this->InstanceID.'networks', json_encode($networks, true));
			
		} 
		
		IPS_LogMessage('CloudTrax',"Apply - Set buffer to: ".$this->GetBuffer($this->InstanceID.'networks'));
			
		$this->RegisterMessage(0, IPS_KERNELMESSAGE);
		
		
		
    }
	
	public function MessageSink($TimeStamp, $SenderID, $Message, $Data) {
		switch ($Message) {
			case IPS_KERNELMESSAGE:
				switch ($Data[0]){
					case KR_READY:
						IPS_LogMessage('CloudTrax', 'Kernel ready!');
						break;
					
				}
				break;
		}	
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
