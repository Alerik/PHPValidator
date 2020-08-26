<?php
require_once('validator.php');
require_once('authentication.php');
validate(array(
	"POST"=>array(
		new Func('login', array(
			new Argument('email', 'string', Validator::EMAIL()),
			new Argument('password', 'string')
		), false),
		new Func('renew', array(
			new Argument('jwt', 'string')
		), false)
	)
));

function none(){
	var_dump(getallheaders());
	echo('Authorization is ' . getallheaders()['Authorization']);
}

function login($email, $password, $conn){
	return auth_login($email, $password, $conn);
}

function renew($jwt){

}
?>
