<?php
// The logout script must start the session, destroy it and then redirect
// to somewhere else. Note: it might be a good idea to add CSRF protection
// here in case someone sends a link hidden in this page somehow. For more
// information about CSRF you could visit Coding Horror. 

include_once 'functions.php';
sec_session_start();

// Unset all session values
$_SESSION = array();

// get session parameters
$params = session_get_cookie_params();

// Delete the actual cookie.
setcookie(session_name(),
        '', time() - 42000,
        $params["path"],
        $params["domain"],
        $params["secure"],
        $params["httponly"]);

// Destroy session
session_destroy();
header('Location: index.php');
