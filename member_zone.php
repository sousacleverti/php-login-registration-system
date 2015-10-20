<?php 
include_once 'db_connect.php';

$query = $mysqli->query("SELECT id, username, email "
        . "FROM members WHERE username = " . $_SESSION['username']);
echo $query;


?>
