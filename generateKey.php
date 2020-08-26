<?php
$secret = bin2hex(random_bytes(32));
echo("Secret:\n");
echo($secret);
echo("\n");
echo("Place this in your config.ini file\n");
