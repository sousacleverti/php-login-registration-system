<?php
// One of the most common problems with authentication systems is the developer
// forgetting to check if the user is logged in. It is very important you use
// the code below on every protected page to check that the user is logged in.
// Make sure to use this function to check if the user is logged in.
include_once 'db_connect.php';
include_once 'functions.php';
 
sec_session_start();
?>
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>Secure Login: Protected Page</title>
        <link rel="stylesheet" href="css/main.css" />
    </head>
    <body>
        <?php if (login_check($mysqli) == true) : ?>
        <h1>Welcome <strong><?php echo htmlentities($_SESSION['username']); ?></strong>!</h1>
            <p>
                This is an example protected page.  To access this page, users
                must be logged in.  At some stage, we'll also check the role of
                the user, so pages will be able to determine the type of user
                authorised to access the page.
            </p>
            <h2>
                <?php
                    $query = 'SELECT id, username, email FROM members WHERE '
                            . 'username = "' . htmlentities($_SESSION['username']) . '";';
                    $result = $mysqli->query($query);
                    if ($result->num_rows > 0) {
                        // output data of each row
                        while ($row = $result->fetch_assoc()) {
                            echo "User id: " . $row["id"] . "<br>User name: " . $row["username"] . "<br>E-mail: " . $row["email"] . "<br>";
                        }
                    } else {
                        echo "0 results: Some problem has occured...";
                    }
                    ?>
            </h2>
            <p><?php include 'member_zone.php' ?></p>
            <h3 class="footer"><strong><a href="logout.php">Logout</a></strong></h3>
        <?php else : ?>
            <p>
                <span class="error">You are not authorized to access this page.</span> Please <a href="index.php">login</a>.
            </p>
        <?php endif; ?>
    </body>
</html>