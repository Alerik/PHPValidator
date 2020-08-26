<?php
require_once('config.php');
// PHP Data Objects(PDO) Sample Code:
function connect(){
	try {
	    $conn = new PDO("sqlsrv:server=" . DBENDPOINT. ", " . DBPORT . "; Database=" . DATABASE, DBUSER, DBPASSWORD);
	    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	    return $conn;
	}
	catch (PDOException $e) {
	    print("Error connecting to SQL Server.");
	    die(print_r($e));
	}
}
?>
