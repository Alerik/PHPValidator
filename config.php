<?php
$config = parse_ini_file('config.ini');

define('DEBUG', $config['debug']);

define('DATABASE', $config['database']);
define('DBENDPOINT', $config['dbendpoint']);
define('DBPORT', $config['dbport']);
define('DBUSER', $config['dbuser']);
define('DBPASSWORD', $config['dbpassword']);

define('JWTTIMEOUT', $config['jwttimeout']);
define('JWTSECRET', $config['jwtsecret']);
?>
