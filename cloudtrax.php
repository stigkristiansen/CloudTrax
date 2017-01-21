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
	
	protected function CallApiServer($method, $endpoint, $data) {
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

class CloudTraxNetwork extends CloudTraxCommunication{
	private $networkId;
	private $ssids;
	
	public function __construct($NetworkId, $Key, $Secret) {
		parent::__construct($Key, $Secret);
		
		$this->networkId = $NetworkId;
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
		$ssid = $this->GetSSIDNumberByName($SSID);
		
		if($ssid){
			$data = array( 'ssids' => 
				array( strval($ssid) => 
	                array( 'general' => 
	                    array( 'enable' => $Enable )
	                )
	            )
	        );
			
			$result = json_decode($this->CallApiServer(Method::PUT, "/network/".strval($this->networkId)."/settings", $data),true);
			
			if(array_key_exists('errors', $result))
				return false;
			else
				return true;
					
		} else 
			return false;

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
			
				$result = json_decode($this->CallApiServer(Method::PUT, "/network/".strval($this->networkId)."/settings", $data),true);
				
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
		$jsonResult = $this->CallApiServer(Method::GET, "/network/".$this->networkId."/settings", NULL);
		
		$ids = json_decode($jsonResult, true)['ssids'];
		
		foreach($ids as $row) {
			$name = strtolower($row['general']['ssid_name']);
			$id =   $row['general']['ssid_num'];
			$returnValue[] = Array('name' => $name, 'number' => $id );
		}
	
		return $returnValue;
		
	}
}

class CloudTraxNetworks extends CloudTraxCommunication {
	private $networks=false;
	
	private $key; // '5e7a64754d6156de1e19896d57a2d6706fd22c0949ca924aea2f4653b141585c'
	private $secret; // '3d9430cd14288e2d0521997f15188e53c161732a71bdce0712258eaf48c8bc5b'
	
	public function __construct($Key, $Secret) {
		parent::__construct($Key, $Secret);
		
		$this->networks = $this->ListNetworks();
	}
	
	public function RefreshData() {
		$this->networks = $this->ListNetworks();
			
	}
	
	public function GetNetworkIdByName($Network) {
		$found = false;
		
		$Network = strtolower($Network);
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
		$jsonResult = $this->CallApiServer(Method::GET, "/network/list", NULL);
		$result = json_decode($jsonResult, true)['networks'];
		
		foreach($result as $row) {
			$name = strtolower($row['name']);
			$id =   $row['id'];
			$returnValue[] = Array('name' => $name, 'id' => $id );
		}
		
		return $returnValue;
				
	}

}

?>