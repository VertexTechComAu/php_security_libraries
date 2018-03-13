# php_security_libraries
PHP security functions and libraries

What is it?
-----------

These is a location for a number of php security libraries you can use to improve security.

Rate Limiter - How does it work?
-----------------

It is as simple as including the rate_limiter.php and using the function.

As an example if you want to block too many login attempts, you could check the IP ($_SERVER['REMOTE_ADDR']) and if more than 50 attempts in 1hour (3600), block any access to the page. The resource name we picked is 'login_page', but this can be any value just as long as you use the same value for the same rate_limit.:

``` php
<?php

require_once('rate_limiter.php');

//Check if they have gone over the rate limit before starting, but don't add the IP to the rate limit
if (!check_within_rate_limit('login_page', $_SERVER['REMOTE_ADDR'], 50, 3600, 0))
{
  die("Your IP has been restricted because of too many attempts. Please try again later.\n");
}

//Login Code

//Add to rate limit after a login attempt (failed or successful) to make it harder to brute force passwords
if (!check_within_rate_limit('login_page', $_SERVER['REMOTE_ADDR'], 50, 3600, 1))
{
  die("Your IP has been restricted because of too many attempts. Please try again later.\n");
}


?>
```


Another example might be a intensive graphs and processing page, and to reduce chance of being used to overload server. So limit to 2 uses every 5minutes

``` php
<?php

include('rate_limiter.php');

if (!check_within_rate_limit('heavy_processing', $_SERVER['REMOTE_ADDR'], 2, 300, 1))
{
  die("Your IP has been restricted because of too many attempts. Please try again later.\n");
}

//Intensive processing code

?>
```

Last example will be a bit more complicated to provide short burst protection as well as large numbers. Lets say this is a way to post a comment. So we want to limit posting by user for a comment to 5 per minute, but also want to limit to only 30 in an hour.

``` php
<?php

include('rate_limiter.php');

if (!check_within_rate_limit('comment', $username, 5, 60, 0))
{
  die("Your IP has been restricted because of too many attempts. Please try again later.\n");
}

if (!check_within_rate_limit('comment', $username, 30, 3600, 1))
{
  die("Your IP has been restricted because of too many attempts. Please try again later.\n");
}

//Code to post comment

?>
```
