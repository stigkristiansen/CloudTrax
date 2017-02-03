<?

class Method {
    const GET = 0;
    const POST = 1;
    const PUT = 2;
    const DELETE = 3;
    
    public static function nameForEnumValue($value) {
        switch($value) {
            case 0: return "GET";
            case 1: return "POST";
            case 2: return "PUT";
            case 3: return "DELETE";
        }
    }
}

class CloudTraxCommunication {
	private $key;
	private $secret;
	private $log=false;
	private $instanceName='';
	
	public function __construct($Key, $Secret) {
		$this->key = $Key;
		$this->secret = $Secret;
		
	}
	
	public function ConfigureLogging($Log, $InstanceName){
		$this->log = $Log;
		$this->instanceName = $InstanceName;
	}
	
	public function Log() {
		return $this->log;
	}
	
	public function InstanceName() {
		return $this->instanceName;
	}
	
	public function CallApiServer($method, $endpoint, $data) {
	    global $key, $secret;
	    
	    $time = time();
	    $nonce = rand();
	    if ($method == Method::POST  && $data==NULL)
	        throw new Exception('POST requires $data');
	    elseif (($method == Method::GET || $method == Method::DELETE) && $data!=NULL) 
	        throw new Exeption('GET and DELETE do not use $data');
	        
	    $path = $endpoint;
	        
		if ($data != NULL) {
	    	$json = json_encode($data);
	        $path .= $json;
	    } else
			$json = "";
		
		$body="";
	    
		$authorization = "key=" . $this->key . ",timestamp=" . $time . ",nonce=" . $nonce;
	    $signature =  hash_hmac('sha256', $authorization . $path . $body, $this->secret);
	    $headers = $this->BuildHeaders($authorization, $signature);
	 
	    return $this->InvokeCurl($method, $endpoint, $headers, $json);
	
	}
	
	//private functions

	private function BuildHeaders($auth, $sign) {
	    $headers = array();
	    $headers[] = "Authorization: " . $auth;
	    $headers[] = "Signature: " . $sign;
	    $headers[] = "Content-Type: application/json";
	    $headers[] = "OpenMesh-API-Version: 1";
	    return $headers;

	}
	
	private function InvokeCurl($method, $endpoint, $headers, $json) {
	    $apiServer = 'https://api.cloudtrax.com';
	    try {
	        $ch = curl_init($apiServer.$endpoint);
	        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
	        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	    
	        if ($method == Method::DELETE)
	            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "DELETE");
	        elseif ($method == Method::PUT) {
	            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "PUT");
	            curl_setopt($ch, CURLOPT_POSTFIELDS, $json);
	        }
	        else if ($method == Method::POST) {
	            curl_setopt($ch, CURLOPT_POST, 1);
	            curl_setopt($ch, CURLOPT_POSTFIELDS, $json);
	        }
	        
	        $result = curl_exec($ch);
			
			if ($result == FALSE) {
	            if (curl_errno($ch) == 0)
	                throw new Exeption('This API call appears to be broken' . '\n');
	            else
	                throw new Exception(curl_error($ch), curl_errno($ch));    
	        }
	        else
	            return $result;
	    } catch(Exception $e) {
	        throw new Exeption(sprintf('Curl failed with error #%d: "%s"', $e->getCode(), $e->getMessage()));
	    }
	
	}
	
	
}

class CloudTraxNetwork {
	private $networkId;
	private $ssids;
	private $com;
	
	public function __construct($Com, $NetworkId) {
		$this->networkId = $NetworkId;
		$this->com = $Com;
		
	}
	
	public function GetSSIDs() {
		return $this->ssids;
	}
	
	public function SetSSIDs($SSIDs) {
		$this->ssids = $SSIDs;
	}
		
	public function Refresh() {
		$this->ssids = $this->ListSSIDs();
	}
	
	public function EnableSSID($SSID, $Enable) {
		$ssid = $this->GetSSIDNumberByName($SSID);
		
		$log = new CTLogging($this->com->Log(), $this->com->InstanceName());
		//echo "SSID number is: ".$ssid;
		                                      	
		if($ssid){
			$data = array( 'ssids' => 
				array( strval($ssid) => 
	                array( 'general' => 
	                    array( 'enable' => $Enable )
	                )
	            )
	        );
						
			try {
				$result = json_decode($this->com->CallApiServer(Method::PUT, "/network/".strval($this->networkId)."/settings", $data),true);
			} catch (Exeption $e) {
				$log->LogMessageError($e->errorMessage);
				return false;
			}
			
			if(array_key_exists('errors', $result)) {
				$errorMessage = '';
				foreach($result['errors'] as $error) {
						$errorMessage.=strlen($errorMessage)==0?$error['message']:', '.$error['message'];
				}
				$log->LogMessageError($errorMessage);
				return false;
			 } else
				return true;
					
		} else {
			$log->LogMessageError('Invalid SSID spesified: '.$SSID);
			return false;
		}
			

	}
	
	public function EnableHidden($SSID, $Enable) {
		$log = new CTLogging($this->com->Log(), $this->com->InstanceName());
		
		$ssid = $this->GetSSIDNumberByName($SSID);
		//echo "SSID number is: ".$ssid;
		                                      	
		if($ssid){
			$data = array( 'ssids' => 
				array( strval($ssid) => 
	                array( 'general' => 
	                    array( 'enable_hidden_network' => $Enable )
	                )
	            )
	        );
			
			try{
				$result = json_decode($this->com->CallApiServer(Method::PUT, "/network/".strval($this->networkId)."/settings", $data),true);
			} catch(Exeption $e) {
				$log->LogMessageError($e->errorMessage);
				return false;
			}
			
			if(array_key_exists('errors', $result)) {
				$errorMessage = '';
				foreach($result['errors'] as $error) {
					$errorMessage.=strlen($errorMessage)==0?$error['message']:', '.$error['message'];
				}
				$log->LogMessageError($errorMessage);
				return false;
			} else
				return true;
					
		} else {
			$log->LogMessageError('Invalid SSID spesified: '.$SSID);
			return false;
		}

	}
	
	public function SetBridgedWiredClients($SSID) {
		$log = new CTLogging($this->com->Log(), $this->com->InstanceName());
				
		$id = $this->GetSSIDNumberByName($SSID);
												
		if($id){
			$data = array('network' => 
						array('advanced' => 
							array('wired_bridge_ssid' => $id)
						)
			);
			
			try{
				$result = json_decode($this->com->CallApiServer(Method::PUT, "/network/".strval($this->networkId)."/settings", $data),true);
			} catch (Exeption $e) {
				$log->LogMessageError($e->errorMessage);
				return false;
			}
			
			if(array_key_exists('errors', $result)) {
				$errorMessage = '';
				foreach($result['errors'] as $error) {
					$errorMessage.=strlen($errorMessage)==0?$error['message']:', '.$error['message'];
				}
				$log->LogMessageError($errorMessage);
				return false;
			}else
				return true;
					
		} else {
			$log->LogMessageError('Invalid SSID spesified: '.$SSID);
			return false;
		}
		
	}

	
	// private functions
	
	private function GetSSIDNumberByName($Name) {
		$found = false;
		
		$Name = strtolower($Name);
		
		if(!$this->ssids)
			return false;
		
		foreach($this->ssids as $ssid) {
			if($ssid['name']==$Name) {
				$found = true;
				$num = $ssid['number'];		
			}
		}
		
		if($found)
			return $num;
		else 
			return 0;
	
	}

	private function ListSSIDs() {
		$log = new CTLogging($this->com->Log(), $this->com->InstanceName());
		
		try {
			$result = json_decode($this->com->CallApiServer(Method::GET, "/network/".$this->networkId."/settings", NULL),true);
		} catch (Exeption $e) {
			$log->LogMessageError($e->errorMessage);
			return NULL;
		}
		
		if(array_key_exists('errors', $result)) {
			$errorMessage = '';
			foreach($result['errors'] as $error) {
				$errorMessage.=strlen($errorMessage)==0?$error['message']:', '.$error['message'];
			}
			$log->LogMessageError($errorMessage);
			return NULL;
		}
		
		if(array_key_exists('ssids', $result))
			$ids = $result['ssids'];
		else {
			$log->LogMessageError('Missing SSIDSs in the response data: '.print_r($result, true));
			return NULL;
		}
				
		foreach($ids as $row) {
			$name = strtolower($row['general']['ssid_name']);
			$id =   $row['general']['ssid_num'];
			$returnValue[] = Array('name' => $name, 'number' => $id );
		}
	
		return $returnValue;
		
	}
}

class CloudTraxNetworks {
	private $networks=false;
	private $com;
	
	public function __construct($Com) {
		$this->com = $Com;
	
	}
	
	public function Refresh() {
		$this->networks = $this->ListNetworks();
			
	}
	
	public function GetNetworks() {
		return $this->networks;
		
	}
	
	public function GetNetworkIdByName($Network) {
		$found = false;
		
		foreach($this->networks as $network) {
			if(strtolower($network['name'])==$Network) {
				$found = true;
				$id = $network['id'];		
			}
		}
		
		if($found)
			return $id;
		else 
			return 0;
	
	}
			
	private function ListNetworks() {
		$log = new CTLogging($this->com->Log(), $this->com->InstanceName());
		
		try{
			$result = json_decode($this->com->CallApiServer(Method::GET, "/network/list", NULL), true);
		} catch (Exeption $e) {
			$log->LogMessageError($e->errorMessage);
			return NULL;
		}
		
		if(array_key_exists('networks', $result))
			$networks = $result['networks'];
		else {
			$log->LogMessageError('Missing networks in the response data:'.print_r($result, true));
			return NULL;
		}
		
		foreach($networks as $row) {
			$name = $row['name'];
			$id =   $row['id'];
			$returnValue[] = Array('name' => $name, 'id' => $id );
		}
		
		return $returnValue;
				
	}

}


?>