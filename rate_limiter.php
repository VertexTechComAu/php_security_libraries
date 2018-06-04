<?php

/*  
Name: PHP Rate Limiter
File: rate_limiter.php
Description: This program provides a simple method of files to provide rate limiting for a PHP website. This means to work it does not require any special database or memory service (like memcached). Hence using this rate limiter over alternatives that use memcached could reduce the attack options and avoid vulnerabilities such as CVE-2016-8706 and CVE-2017-9951.
Furthermore it is built to perform the minimum disk read/s and writes and possible, as to avoid being a performance bottleneck.

Copyright: 2018 Vertex Technologies Pty Ltd (ABN: 67 611 787 029)
License:
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

DEFINE ('RATE_LIMITER_FOLDER', '/tmp/php_rate_limiter');
DEFINE ('MAXIMUM_RATE_AGE_IN_SECONDS', '86400');
DEFINE ('INCLUDE_READABLE_COMMENT', 'FALSE');

//Will return false if more than $rate_per_period has occurred in time frame. i.e. false starting from $rate_per_period + 1
function check_within_rate_limit($resource, $limit_group, $rate_per_period, $period_in_seconds, $add_to_rate)
{

	$rate_limiter_folder = RATE_LIMITER_FOLDER;
	$maximum_rate_age_in_seconds = MAXIMUM_RATE_AGE_IN_SECONDS;
	$rate_counter = 0;
	
	//Remove any trailing slashes
	while (strlen($rate_limiter_folder) > 1 && substr ( $rate_limiter_folder , -1 ) == DIRECTORY_SEPARATOR)
	{
		$rate_limiter_folder = substr ( $rate_limiter_folder , 0, -1 );
	}
	
	//Check and try and create the base folder
	if (!file_exists ( $rate_limiter_folder ))
	{
		if (!mkdir( $rate_limiter_folder ))
		{
			die('Rate limiter folder failed to be created');
		}
	}
	
	$resource_hash = hash('sha256', $resource); //hash for uniqueness and to avoid inappropriate characters
	//check folder exists and create if it doesn't
	if (!file_exists ( $rate_limiter_folder. DIRECTORY_SEPARATOR .$resource_hash ))
	{
		if (!mkdir( $rate_limiter_folder. DIRECTORY_SEPARATOR .$resource_hash ))
		{
			die('Resource Rate limiter folder failed to be created');
		}
	}
	
	$limit_group_hash = hash('sha256', $limit_group); //hash for uniqueness and to avoid inappropriate characters

	//check file exists and create if it doesn't
	if ( !file_exists ( $rate_limiter_folder.DIRECTORY_SEPARATOR .$resource_hash. DIRECTORY_SEPARATOR .$limit_group_hash ) || filemtime ( $rate_limiter_folder. DIRECTORY_SEPARATOR .$resource_hash. DIRECTORY_SEPARATOR .$limit_group_hash ) < (time() - $maximum_rate_age_in_seconds) )
	{
	
		if ($add_to_rate == 0) //skip if we have selected to add nothing
		{
			return TRUE;
		}
	
		$file_handle = fopen($rate_limiter_folder. DIRECTORY_SEPARATOR .$resource_hash. DIRECTORY_SEPARATOR .$limit_group_hash, 'w');
		if ($file_handle)
		{
			if (INCLUDE_READABLE_COMMENT == 'TRUE')
			{
				fwrite ( $file_handle , '# ' . $resource . ',' .$limit_group."\n" );
			}
			
			while ($add_to_rate > 0)
			{
				fwrite ( $file_handle , time()."\n" );
				$add_to_rate--;
			}
			
			fclose($file_handle);
			
			if (rand (1 , 1000) == 1)
			{
				clean_directory($rate_limiter_folder. DIRECTORY_SEPARATOR .$resource_hash. DIRECTORY_SEPARATOR, $age_in_seconds);
			}
			
			
			return TRUE;
		}
		
	}
	else
	{
	
		$filesize = filesize( $rate_limiter_folder. DIRECTORY_SEPARATOR .$resource_hash. DIRECTORY_SEPARATOR .$limit_group_hash );
	
		
		if (INCLUDE_READABLE_COMMENT == 'TRUE')
		{
			//skip the length of the first line as it contains the comment
			$filesize = $filesize - strlen('# ' . $resource . ',' .$limit_group."\n"); 
		}
		
		
		$rate_counter = intval(($filesize)/11); //10 characters for unix epoch time (in seconds) + 1 for newline char
		
		
		$file_handle = fopen($rate_limiter_folder. DIRECTORY_SEPARATOR .$resource_hash. DIRECTORY_SEPARATOR .$limit_group_hash, 'a+');
		
		//check if there are enough characters to see if we even need to count the number of events
		if ($rate_counter >= $rate_per_period)
		{
			fseek ($file_handle , (-11*($rate_per_period)), SEEK_END);
			$buffer = fgets($file_handle, 4096);
			
			if ( $buffer >= (time() - $period_in_seconds) )
			{
				$rate_counter = $rate_per_period + 1;
			}
			else
			{
				$rate_counter = $rate_per_period - 1;
			}
			
		}	
		
		fseek ($file_handle , 0, SEEK_END);
		while ($add_to_rate > 0)
		{
			fwrite ( $file_handle , time()."\n" );
			$add_to_rate--;
		}
		fclose($file_handle);
		
	
	}

	//Only spend the time to cleanup the files in the folder every so often
	if (rand (1 , 1000) == 1)
	{
		clean_directory($rate_limiter_folder. DIRECTORY_SEPARATOR .$resource_hash , $age_in_seconds);
	}

	if ($rate_counter >= $rate_per_period)
	{
		return false;
	}
	
	return true;
}


//delete files over a certain age
function clean_directory($directory, $age_in_seconds)
{

   $cdir = scandir($directory); 
   foreach ($cdir as $key => $value) 
   { 
         if (!is_dir($dir . DIRECTORY_SEPARATOR . $value)) 
         { 
         	if (filemtime ($dir . DIRECTORY_SEPARATOR . $value)  < (time() - $age_in_seconds) )
         	{
         		unlink ($dir . DIRECTORY_SEPARATOR . $value);
         	} 
         } 
   } 

}




?>
