<?

require_once(__DIR__ . "/../logging.php");
require_once(__DIR__ . "/../cloudtrax.php");

class CloudTraxNetwork extends IPSModule {

   public function Create(){
        parent::Create();
        
        $this->RegisterPropertyBoolean ("Log", false );
		
		$this->RegisterPropertyString("key", "");
		$this->RegisterPropertyString("secret", "");

   }

    public function ApplyChanges(){
        parent::ApplyChanges();
		
		$key = $this->ReadPropertyString('key');
		if(strlen($key)==0)
			return;
		
		$secret = this->ReadPropertyString('secret');
		if(strlen($secret)==0)
			return;
		
		
		
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
