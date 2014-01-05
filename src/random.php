<?php

require_once __DIR__ . '/string_tools.php';


/**
 * Generate stronger random numbers.
 *
 * The current implementation tries the following randomness sources:
 * - the OpenSSL extension
 * - the Mcrypt extension
 * - /dev/urandom
 */
class Random
{

    /**
     * Generate a certain number of pseudo-random bytes.
     *
     * Note: This method is *not* suitable for obtaining cryptographically secure random numbers.
     *
     * @param int $numberBytes The number of bytes to generate
     *
     * @return string The resulting bytes
     *
     * @throws InvalidArgumentException if the number of bytes is not a positive integer
     * @throws Exception                if no randomness source is available
     * @throws RuntimeException         if the result is not a string with the specified number of bytes
     */
    public static function generateBytes($numberBytes)
    {
        if (!is_int($numberBytes) || $numberBytes <= 0)
            throw new InvalidArgumentException('Number of bytes must be a positive integer.');

        $generatedBytes = null;

        if (function_exists('openssl_random_pseudo_bytes'))
            $generatedBytes = openssl_random_pseudo_bytes($numberBytes);
        elseif (function_exists('mcrypt_create_iv'))
            $generatedBytes = mcrypt_create_iv($numberBytes, MCRYPT_DEV_URANDOM);
        else
        {
            /*
             * Try reading from /dev/urandom as the last resort. Since this is an OS-specific device,
             * make sure to suppress warnings.
             *
             * Note that using is_readable() would *not* fix the problem of unwanted warnings, because
             * it may still emit open_basedir warnings. This wouldn't make sense on, say, a Windows
             * system.
             */
            $urandom = @fopen('/dev/urandom', 'rb');

            if (!is_resource($urandom))
                throw new Exception('No randomness source available. You need the OpenSSL extension or the Mcrypt extension or access to /dev/urandom.');

            $generatedBytes = fread($urandom, $numberBytes);
            fclose($urandom);
        }

        if (!is_string($generatedBytes) || StringTools::byteLength($generatedBytes) < $numberBytes)
            throw new RuntimeException('Failed to generate random bytes.');

        return $generatedBytes;
    }

    /**
     * Generate a certain number of pseudo-random bytes and return its hexadecimal representation.
     *
     * @see Random::generateBytes()
     *
     * @param int $numberBytes The number of bytes to generate
     *
     * @return string The encoded bytes
     */
    public function generateHexBytes($numberBytes)
    {
        return bin2hex(self::generateBytes($numberBytes));
    }

}
