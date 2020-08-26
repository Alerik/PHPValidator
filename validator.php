<?php
//Use for validating input from GET/POST requests and resolving proper function
//TODO:
//Add support for _FILES

require_once('database.php');
require_once('authentication.php');
require_once('config.php');

//This is for stuff like: 'You have to many entries in the table' or 'You're not allowed to change your username'
//User on website sees this to some capacity
//These are called from the actual methods
//Return a 500 error with an error message or something
class UserError extends Exception {

}

//This is for stuff like: 'You are not a user, so you can't upload a blob!'
//Should only be seen by malicous peeps
//Return 401
class AuthorizeError extends Exception{

}

//This is for stuff like: 'Invalid arguments used here' or 'Was expecting a string'
//The network errors for debugging from browser/curl
//Return a 400 error
class ClientError extends Exception {

}

//This is for stuff like: 'DELETE is not a valid method to handle' or 'Your callback function isn't defined'
//The PHP programmer sees this
//Return a 501 error
class ProgrammerError extends Exception {

}

//Returns a lower-case uuid if valid, otherwise don't
function filter_uuid($str){
	if (!is_string($str) || (preg_match('/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/', $str) !== 1)) {
		return false;
	}

	return strtolower($str); 
}

//Used for validating inputs
class Validator{
	public $name;
	public $filter;
	public $options;

	function __construct($name, $filter, $options = array()){
		$this->name = $name;
		$this->filter = $filter;
		$this->options = $options;
	}

	//Used for validator generation
	static function generate_max_length($max){
		return function($str) use ($max) {
			if(strlen($str) <= $max)
				return $str;
			else
				return false;
		};
	}
	static function generate_min_length($min){
		return function($str) use ($min) {
			if(strlen($str) >= $min)
				return $str;
			else
				return false;
		};
	}

	//Basic validators
	public static function UUID(){
		return new Validator('UUIDValidator', FILTER_CALLBACK, array('options'=>'filter_uuid'));
	}
	public static function EMAIL(){
		return new Validator('EMAILValidator', FILTER_VALIDATE_EMAIL);
	}
	public static function URL(){
		return new Validator('URLValidator', FILTER_VALIDATE_URL);
	}

	//Make sure string has same or more characters
	public static function MINLENGTH($min){
	      return new Validator('MINLEN'.$min.'Validator', FILTER_CALLBACK, array('options' => self::generate_min_length($min)));
	}
	//Make sure string has same or less characters
	public static function MAXLENGTH($max){
	      return new Validator('MAXLEN'.$max.'Validator', FILTER_CALLBACK, array('options' => self::generate_max_length($max)));
	}
}

class Argument{
	public $name;
	public $type;
	public $validators;
	public $authorized;

	//If authorized, look in the JWT payload
	function __construct($name, $type, $validators = array(), $authorized = false){
		$this->name = $name;
		$this->type = $type;
		$this->authorized = $authorized;

		//Handle single validator or array of validators
		if(is_array($validators))
			$this->validators = $validators;
		else
			$this->validators = array($validators);
	}

	function isFile(){
		return $this->type == 'file';
	}
}

class Func{
	public $name;
	public $arguments;
	public $authorized;

	//authorized: Whether or not to look at the Authorization header for a JWT
	function __construct($name, $arguments, $authorized = true){
		$this->name = $name;
		$this->arguments = $arguments;
		$this->authorized = $authorized;
	}

	//Convenience function
	function getNormalKeys(){
		$names = array();
		foreach($this->arguments as $argument){
			if(!$argument->authorized)
				array_push($names, $argument->name);
		}

		return $names;
	}

	function getAuthKeys(){
		$names = array();

		foreach($this->arguments as $argument){
			if($argument->authorized)
				array_push($names, $argument->name);
		}

		return $names;
	}
}

//Return true if all of keys2 are in keys1
function compatibleKeys($keys1, $keys2){
	foreach($keys2 as $key){
		if(!in_array($key, $keys1))
			return false;
	}

	return true;
}

//Process input and cast to proper PHP type
function strToVal($str){
	if(filter_var($str, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE) !== NULL){
		return boolval($str);
	}
	else if(filter_var($str, FILTER_VALIDATE_INT)){
		return intval($str);
	}
	else if(filter_var($str, FILTER_VALIDATE_FLOAT)){
		return floatval($str);
	}
	else{
		return $str;
	}

}

//Exit gracefully with right response code
//If $debug_only is on, won't print the error message unless in debug mode
function handleError($exceptions, $http_code, $debug_only = false){
	//If there are no errors
	if($exceptions === NULL || (is_array($exceptions) && sizeof($exceptions) == 0)){
		return;
	}

	//Print only when it should
	if(($debug_only && DEBUG) || !$debug_only){
		if(is_array($exceptions)){
			foreach($exceptions as $e){
				print($e->getMessage().'\n');
			}
		}
		else{
			print($exceptions->getMessage().'\n');
		}
	}

	http_response_code($http_code);
	exit();
}

//Check for function declarations/validators ahead of time
function preRunCheck($endpoints){
	$exceptions = array();
	foreach($endpoints as $endpoint){
		foreach($endpoint as $func){
			try{
				if(!function_exists($func->name)){
					throw new ProgrammerError('Function ' . $func->name . ' does not exist.');
				}
			}
			catch(ProgrammerError $e){
					array_push($exceptions, $e);	
			}
			try{
				foreach($func->arguments as $arg){
					if($arg->authorized && !$func->authorized){
						throw new ProgrammerError('Function ' . $func->name . ' has authorized arguments, however, does not require authentication.');
					}
				}
			}
			catch(ProgrammerError $e){
				array_push($exceptions, $e);	
			}
		}
	}
	return $exceptions;
}

//Call with something like:
//validate(array(
//'GET'=>array(
//	new Func('func1', array(
//		new Argument('user_id', 'string', Validator::UUID()),
//		new Argument('ad_id', 'string', Validator::UUID()),
//		new Argument('name', 'string', Validator::MAXLENGTH(20))
//	))
//)
//)
function validate($endpoints){
	//Only check for dumb errors when in debug, like if functions exist and whatnot
	if(DEBUG){
		$preRunExceptions = preRunCheck($endpoints);
		handleError($preRunExceptions, 501, true);
	}
	
	//Find the right method to use
	$method = $_SERVER['REQUEST_METHOD'];

	try{
		//No valid endpoint for this method, exit
		if(!array_key_exists($method, $endpoints)){
			if($method !== 'OPTIONS')
				throw new ClientError('HTTP Method ' . $method . ' is not supported');
			else{
				http_response_code(200);
				header('Allow: GET, POST');
				exit();
			}
		}
	} catch (ClientError $e){
		handleError($e, 405);
	}

	$functions = $endpoints[$method];
	$METHOD_VAR = null;

	if($method == 'GET')
		$METHOD_VAR = $_GET;
	else if ($method == 'POST')
		$METHOD_VAR = $_POST;

	$headers = getallheaders();
	$isUsingAuthentication = array_key_exists('Authorization', $headers);
	$authorization = $isUsingAuthentication ? $headers['Authorization'] : NULL;
	$authorized = verifyHeader($authorization);
	$auth_arg_keys = array();
	
	if($authorized != false){
		$auth_arg_keys = array_keys($authorized);
	}

	//Find the correct function to use
	//We should not stick JWT tokens here, it's a security flaw
	//It might match user_id or something with a non-secure argument instead of the JSON one
	//Which could be kinda bad
	$supplied_keys = array_keys($METHOD_VAR);

	$compatible = null;
	$compatible_count = 0;
	foreach($functions as &$func){
		$normal_keys = $func->getNormalKeys();
		$auth_keys = $func->getAuthKeys();

		if(compatibleKeys($supplied_keys, $normal_keys) //Check that all standard keys are here
			&& compatibleKeys($auth_arg_keys, $auth_keys)){ //Check all auth keys
			//Use first by default
			if($compatible_count == 0)
				$compatible = $func;
			$compatible_count++;
		}
	}

	try{
		//No compatible functions found
		if($compatible_count == 0){
			throw new ClientError('Arguments don\'t match any functions');
		}
	}
	catch(ClientError $e){
		handleError($e, 400);
	}

	try{
		//Multiple compatible functions found
		if($compatible_count > 1){
			//throw new ProgrammerError('Multiple compatible functions, using first.');
		}
	}
	catch(ProgrammerError $e){
		handleError($e, 501, true);
	}

	//If JWT not present or not valid and needs authorization, throw error
	if(!$authorized && $compatible->authorized){
		throw new ClientError('Expected Authentication Header');
	}

	$typed_args = array();
	$exceptions = array();
	//Check the parameters types passed to the function
	//Also check against validators
	foreach($compatible->arguments as $argument){
		$arg_val = '';
		if($argument->isFile()){
			//Open the file as val
			if(isset($_FILES, $argument->name)){
				$diskname = $_FILES[$argument->name]['tmp_name'];
				$arg_val = fopen($diskname, 'r');
			}
			//File not attached, error
			else{
				throw new ClientError('Expected file ' . $argument->name .'.');
			}
		}
		else{
			$arg_val = ($argument->authorized ? strToVal($authorized[$argument->name]) : strToVal($METHOD_VAR[$argument->name]));
			$type = gettype($arg_val);
		
			//Type checking
			//Add some le-way to strings
			try{
				if($type != $argument->type && $argument->type != 'string')
					throw new ClientError('Expected ' . $argument->name . ' to be type ' . $argument->type . ' got ' . $type . ' instead.');
			}
			catch(ClientError $e){
				array_push($exceptions, $e);
			}

			if($argument->type == 'string')
				$arg_val = ($argument->authorized ? strToVal($authorized[$argument->name]) : $METHOD_VAR[$argument->name]);

			//Validator checking
			foreach($argument->validators as $validator){
				try{
					$result = filter_var($arg_val, $validator->filter, $validator->options);
					if(!$result)
						throw new ClientError($argument->name . ' did not pass the ' . $validator->name . ' validator.');
					else //Update the arg_value, useful for stuff like UUIDS where we only want lowercase ones
						$arg_val = $result;
				}
				catch(ClientError $e){
					array_push($exceptions, $e);
				}
			}
					
		}
		$typed_args[$argument->name] = $arg_val;
	}
	handleError($exceptions, 400);


	//Inject database connection
	try{
		$typed_args['conn'] = connect();
	}
	catch(ProgrammerError $e){
		handleError($e, 501, true);	
	}

	//All parameters were correct, run the function now
	try{
		if(function_exists($compatible->name)){
			$result = call_user_func_array($compatible->name, $typed_args);
			print(json_encode($result, JSON_UNESCAPED_SLASHES));
		}
		else
			throw new ProgrammerError('Function ' . $compatible->name . ' does not exist.');
	}
	//Handle errors thrown by the user function
	catch(ProgrammerError $e){
		handleError($e, 501, true);
	}
	catch(ClientError $e){
		handleError($e, 400);
	}
	catch(UserError $e){
		handleError($e, 400);
	}
	catch(AuthorizeError $e){
		handleError($e, 401);
	}
	exit();
}
?>
