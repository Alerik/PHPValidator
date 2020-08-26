<?php

require_once('config.php');
require_once('utils.php');

//Queries server for login and returns JWT
//This needs to be here instead of login.php because
//Including login.php executes that script, whereas this is just a callable function
function auth_login($email, $password, $conn){
	$stm = $conn->prepare('SELECT id, hashword FROM users WHERE email = :email');
	$stm->bindParam(':email', $email, PDO::PARAM_STR);
	$stm->execute();

	$row = $stm->fetch(PDO::FETCH_ASSOC);
	$id = $row['id'];
	$hash = $row['hashword'];
	
	//Password correct, generate JWT
	if(password_verify($password, $hash)){
		return generateJWT($id, 'buyer');
	}
	//Password incorrect
	else{
		return null;
	}
}

function generateJWT($user_id, $role){
	$secret = JWTSECRET;
	
	$header = json_encode([
		'typ' => 'JWT',
		'alg' => 'H256'
	]);

	$exp = strtotime(JWTTIMEOUT);

	$payload = json_encode([
		'user_id' => $user_id,
		'role' => $role,
		'exp' => $exp
	]);

	$base64UrlHeader = base64UrlEncode($header);
	$base64UrlPayload = base64UrlEncode($payload);

	$signature = hash_hmac('sha256', $base64UrlHeader . '.' . $base64UrlPayload, $secret, true);
	$base64UrlSignature = base64UrlEncode($signature);

	$jwt = $base64UrlHeader . '.' . $base64UrlPayload . '.' . $base64UrlSignature;

	return $jwt;
}

function verifyJWT($jwt){
	$secret = JWTSECRET;

	$tokenParts = explode('.', $jwt);
	
	if(sizeof($tokenParts) != 3){
		return false;
	}
	
	$header = base64_decode($tokenParts[0]);
	$payload = base64_decode($tokenParts[1]);
	$signatureProvided = $tokenParts[2];

	$expiration = json_decode($payload)->exp;
	$tokenExpired = ($expiration - time() < 0);

	//Token has expired and is not valid
	if($tokenExpired){
		return false;
	}

	$base64UrlHeader = base64UrlEncode($header);
	$base64UrlPayload = base64UrlEncode($payload);
	$signature = hash_hmac('sha256', $base64UrlHeader . '.' . $base64UrlPayload, $secret, true);
	$base64UrlSignature = base64UrlEncode($signature);

	$signatureValid = ($base64UrlSignature === $signatureProvided);

	//Invalid signatures, don't match
	if(!$signatureValid){
		return false;
	}
	$payload = (array) json_decode($payload);
	return $payload;
}

function verifyHeader($header){
	if($header == NULL){
		return false;
	}

	$split = explode(' ', $header);

	$type = $split[0];
	$jwt = $split[1];
	
	return verifyJWT($jwt);
}
?>
