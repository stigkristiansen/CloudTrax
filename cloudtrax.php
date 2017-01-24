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
	
	public function __construct($Key, $Secret) {
		$this->key = $Key;
		$this->secret = $Secret;
	}
	
	public function CallApiServer($method, $endpoint, $data) {
	    global $key, $secret;
	    
	    $time = time();
	    $nonce = rand();
	    if ($method == Method::POST)
	        assert( '$data != NULL /* @@@@ POST requires $data @@@@ */');
	    elseif ($method == Method::GET || $method == Method::DELETE)
	        assert( '$data == NULL /* @@@ GET and DELETE take no $data @@@ */');
	        
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
	                echo "@@@@ NOTE @@@@: nil HTTP return: This API call appears to be broken" . "\n";
	            else
	                throw new Exception(curl_error($ch), curl_errno($ch));    
	        }
	        else
	            return $result;
	    } 
	    catch(Exception $e) {
	        trigger_error( sprintf('Curl failed with error #%d: "%s"',
	            $e->getCode(), $e->getMessage()), E_USER_ERROR);
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
		$this->ssids = $this->ListSSIDs();
	}
	
	public function GetSSIDs() {
		return $this->ssids;
	}
	
	public function SetSSIDs($SSIDs) {
		$this->ssids = $SSIDs;
	}
	
		
	public function GetNetworkJson() {
		$network = array('networkid' => $this->networkId, 'ssids' => $this->ssids);
		return json_encode($network);
	}
	
	public function Refresh() {
		$this->ssids = ListSSIDs($this->networkId);
	}
	
	public function EnableSSID($SSID, $Enable) {
		//$ssid = $this->GetSSIDNumberByName($SSID);
		
		//echo "SSID number is: ".$ssid;
		                                      	
		//if($ssid){
			$data = array( 'ssids' => 
				array( strval($ssid) => 
	                array( 'general' => 
	                    array( 'enable' => $Enable )
	                )
	            )
	        );
			
			$result = json_decode($this->com->CallApiServer(Method::PUT, "/network/".strval($this->networkId)."/settings", $data),true);
			
			if(array_key_exists('errors', $result))
				return false;
			else
				return true;
					
		//} else 
		//	return false;

	}
	
	public function SetBridgedWiredClients($SSID) {
		
		if($this->networkId) {
		
			$id = $this->GetSSIDNumberByName($SSID);
			                                      	
			if($id){
				$data = array('network' => 
							array('advanced' => 
								array('wired_bridge_ssid' => $id)
							)
				);
			
				$result = json_decode($this->com->CallApiServer(Method::PUT, "/network/".strval($this->networkId)."/settings", $data),true);
				
				if(array_key_exists('errors', $result))
					return false;
				else
					return true;
						
			} else 
				return false;
		} else
			return false;

	}

	
	
	
	// private functions
	
	private function GetSSIDNumberByName($Name) {
		$found = false;
		
		$Name = strtolower($Name);
		
		foreach($this->ssids as $ssid) {
			if($ssid['name']==$Name) {
				$found = true;
				$num = $ssid['number'];		
			}
		}
		
		if($found)
			return $num;
		else 
			return false;
	
	}

	private function ListSSIDs() {
		$jsonResult = $this->com->CallApiServer(Method::GET, "/network/".$this->networkId."/settings", NULL);
		
		$ids = json_decode($jsonResult, true)['ssids'];
		
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
		$this->networks = $this->ListNetworks();
	}
	
	public function RefreshData() {
		$this->networks = $this->ListNetworks();
			
	}
	
	public function GetNetworks() {
		if($this->networks)
			return $this->networks;
		else
			return false;
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
			return false;
	
	}
			
	// private functions
	
	private function ListNetworks() {
		$jsonResult = $this->com->CallApiServer(Method::GET, "/network/list", NULL);
		$result = json_decode($jsonResult, true)['networks'];
		
		foreach($result as $row) {
			$name = $row['name'];
			$id =   $row['id'];
			$returnValue[] = Array('name' => $name, 'id' => $id );
		}
		
		return $returnValue;
				
	}

}


?>