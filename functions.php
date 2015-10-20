<?php
include_once 'db_details.php'; 

// Filter data to prevent code injection
function filter($data) {
    $aux = array(array());
    foreach($data as $key => $value) {
        $aux[$key] = trim($value);
        $aux[$key] = stripslashes($value);
        $aux[$key] = htmlspecialchars($value);
    }
    return $aux;
}

// PHP sessions are known not to be secure, therefore it is important not just        
// to put "session_start();" at the top of every page on which you want to use
// PHP sessions. We are going to create a function called "sec_session_start()",
// this will start a PHP session in a secure way. You should call this function
// at the top of any page in which you wish to access a PHP session variable. 
// This function makes your login script a whole lot more secure. It stops
// crackers accessing the session id cookie through JavaScript (for example in
// an XSS attack). Also the "session_regenerate_id()" function, which
// regenerates the session id on every page reload, helps prevent session
// hijacking. Note: If you are using HTTPS in your login application set the
// "$secure" variable to true.
// In a production environment it is essential to use HTTPS.
function sec_session_start() {
    $session_name = 'sec_session_id';   // Set a custom session name
    $secure = SECURE;
    // This stops JavaScript being able to access the session id.
    $httponly = true;
    // Forces sessions to only use cookies.
    if (ini_set('session.use_only_cookies', 1) === FALSE) {
        header("Location: ../error.php?err=Could not initiate a safe session (ini_set)");
        exit();
    }
    // Gets current cookies params.
    $cookieParams = session_get_cookie_params();
    session_set_cookie_params($cookieParams["lifetime"],
        $cookieParams["path"],
        $cookieParams["domain"],
        $secure,
        $httponly);
    // Sets the session name to the one set above.
    session_name($session_name);
    session_start();            // Start the PHP session
    session_regenerate_id(true);    // regenerated the session, delete the old one.
}

// This function will check the email and password against the database.
// It will return true if there is a match
function login($user, $password, $mysqli) {
    // Using prepared statements means that SQL injection is not possible.
    if ($stmt = $mysqli->prepare("SELECT id, username, password, salt
        FROM members
       WHERE username = ?
        LIMIT 1")) {
        $stmt->bind_param('s', $user);  // Bind "$user" to parameter.
        $stmt->execute();    // Execute the prepared query.
        $stmt->store_result();

        // get variables from result.
        $stmt->bind_result($user_id, $username, $db_password, $salt);
        $stmt->fetch();

        // hash the password with the unique salt.
        $password = hash('sha512', $password . $salt);
        if ($stmt->num_rows == 1) {
            // If the user exists we check if the account is locked
            // from too many login attempts

            if (checkbrute($user_id, $mysqli) == true) {
                // Account is locked
                // Send an email to user saying their account is locked
                return false;
            } else {
                // Check if the password in the database matches
                // the password the user submitted.
                if ($db_password == $password) {
                    // Password is correct!
                    // Get the user-agent string of the user.
                    $user_browser = $_SERVER['HTTP_USER_AGENT'];
                    // XSS protection as we might print this value
                    $user_id = preg_replace("/[^0-9]+/", "", $user_id);
                    $_SESSION['user_id'] = $user_id;
                    // XSS protection as we might print this value
                    $username = preg_replace("/[^a-zA-Z0-9_\-]+/",
                                                                "",
                                                                $username);
                    $_SESSION['username'] = $username;
                    $_SESSION['login_string'] = hash('sha512',
                              $password . $user_browser);
                    // Login successful.
                    return true;
                } else {
                    // Password is not correct
                    // We record this attempt in the database
                    $now = time();
                    $mysqli->query("INSERT INTO login_attempts(user_id, time)
                                    VALUES ('$user_id', '$now')");
                    return false;
                }
            }
        } else {
            // No user exists.
            return false;
        }
    }
}

// Brute force attacks are when a hacker tries thousands of different passwords
// on an account, either randomly generated passwords or from a dictionary. In our
// script if a user account has more than five failed logins their account is
// locked. Brute force attacks are hard to prevent. A few ways we can prevent
// them are using a CAPTCHA test, locking user accounts and adding a delay on
// failed logins, so the user cannot login for another thirty seconds.
//
// It's strongly recommend using a CAPTCHA. As yet we have not implemented this
// functionality in the example code, but hope to do so in the near future,
// using SecureImage, since it does not require registration. You may prefer
// something better known such as reCAPTCHA from Google. Whichever system you
// decide on, we suggest you only display the CAPTCHA image after two failed
// login attempts so as to avoid inconveniencing the user unnecessarily.
//
// When faced with the problem of brute force attacks, most developers simply
// block the IP address after a certain amount of failed logins. But there are
// many tools to automate the process of making attacks like these; and these
// tools can go through a series of proxies and even change the IP on each
// request. Blocking all these IP addresses could mean you're blocking
// legitimate users as well. In our code we'll log failed attempts and lock'
// the user's account after five failed login attempts. This should trigger
// the sending of an email to the user with a reset link, but we have not
// implemented this in our code.
function checkbrute($user_id, $mysqli) {
    // Get timestamp of current time
    $now = time();

    // All login attempts are counted from the past 2 hours.
    $valid_attempts = $now - (2 * 60 * 60);

    if ($stmt = $mysqli->prepare("SELECT time
                             FROM login_attempts
                             WHERE user_id = ?
                            AND time > '$valid_attempts'")) {
        $stmt->bind_param('i', $user_id);

        // Execute the prepared query.
        $stmt->execute();
        $stmt->store_result();

        // If there have been more than 5 failed logins
        if ($stmt->num_rows > 5) {
            return true;
        } else {
            return false;
        }
    }
}

// We do this by checking the "user_id" and the "login_string" SESSION
// variables. The "login_string" SESSION variable has the user's browser
// information hashed together with the password. We use the browser
// information because it is very unlikely that the user will change their
// browser mid-session. Doing this helps prevent session hijacking. Add this
// function to your functions.php file in the includes folder of your
// application:
function login_check($mysqli) {
    // Check if all session variables are set
    if (isset($_SESSION['user_id'],
                        $_SESSION['username'],
                        $_SESSION['login_string'])) {

        $user_id = $_SESSION['user_id'];
        $login_string = $_SESSION['login_string'];
        $username = $_SESSION['username'];

        // Get the user-agent string of the user.
        $user_browser = $_SERVER['HTTP_USER_AGENT'];

        if ($stmt = $mysqli->prepare("SELECT password
                                      FROM members
                                      WHERE id = ? LIMIT 1")) {
            // Bind "$user_id" to parameter.
            $stmt->bind_param('i', $user_id);
            $stmt->execute();   // Execute the prepared query.
            $stmt->store_result();

            if ($stmt->num_rows == 1) {
                // If the user exists get variables from result.
                $stmt->bind_result($password);
                $stmt->fetch();
                $login_check = hash('sha512', $password . $user_browser);

                if ($login_check == $login_string) {
                    // Logged In!!!!
                    return true;
                } else {
                    // Not logged in
                    return false;
                }
            } else {
                // Not logged in
                return false;
            }
        } else {
            // Not logged in
            return false;
        }
    } else {
        // Not logged in
        return false;
    }
}

// This function sanitizes the output from the PHP_SELF server variable.
// It is a modificaton of a function of the same name used by the WordPress
// Content Management System
function esc_url($url) {
    if ('' == $url) {
        return $url;
    }

    $url = preg_replace('|[^a-z0-9-~+_.?#=!&;,/:%@$\|*\'()\\x80-\\xff]|i', '', $url);
    $strip = array('%0d', '%0a', '%0D', '%0A');
    $url = (string) $url;

    $count = 1;
    while ($count) {
        $url = str_replace($strip, '', $url, $count);
    }

    $url = str_replace(';//', '://', $url);
    $url = htmlentities($url);
    $url = str_replace('&amp;', '&#038;', $url);
    $url = str_replace("'", '&#039;', $url);

    if ($url[0] !== '/') {
        // We're only interested in relative links from $_SERVER['PHP_SELF']
        return '';
    } else {
        return $url;
    }
}