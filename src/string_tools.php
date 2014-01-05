<?php

/**
 * Various methods for working with strings.
 *
 * This provides security functionalities as well as workarounds for PHP-related issues.
 */
class StringTools
{

    /**
     * Count the number of bytes in a string.
     *
     * We cannot simply use strlen() for this, because it could be overwritten by
     * mbstring.func_overload. In this case, the function operates on *characters* of the
     * internal encoding rather than on raw bytes. Multiple bytes might then be regarded
     * as a single multibyte character.
     *
     * @param string $binaryString The input string
     *
     * @return int The number of bytes
     *
     * @throws RuntimeException if the result is not an integer
     */
    public static function byteLength($binaryString)
    {
        $length = null;

        if (extension_loaded('mbstring'))
            $length = mb_strlen($binaryString, '8bit');
        else
            $length = strlen($binaryString);

        if (!is_int($length))
            throw new RuntimeException('Failed to get string length.');

        return $length;
    }

    /**
     * Get a substring based on byte limits.
     *
     * @see StringTools::byteLength()
     *
     * @param string   $binaryString The input string
     * @param int      $start
     * @param int|null $length
     *
     * @return string The substring
     *
     * @throws RuntimeException if the result is not a string
     */
    public static function byteSubstring($binaryString, $start, $length = null)
    {
        $substring = null;

        if (extension_loaded('mbstring'))
        {
            /*
             * Be careful when passing a null length to mb_substr(), because different PHP versions
             * will react differently, either returning an empty string (PHP 5.3) or everything from
             * $start (PHP >= 5.4). Make sure to always get the latter.
             */
            if (is_null($length))
                $substring = mb_substr($binaryString, $start, self::byteLength($binaryString), '8bit');
            else
                $substring = mb_substr($binaryString, $start, $length, '8bit');
        }
        else
        {
            // See the warning above
            if (is_null($length))
                $substring = substr($binaryString, $start);
            else
                $substring = substr($binaryString, $start, $length);
        }

        if (!is_string($substring))
            throw new RuntimeException('Failed to extract substring.');

        return $substring;
    }

    /**
     * Compare strings without "short-circuiting" in order to mitigate timing attacks.
     *
     * @param string $string1
     * @param string $string2
     *
     * @return boolean Whether the strings are equal
     *
     * @throws InvalidArgumentException if one of the inputs is not a string
     */
    public static function secureCompare($string1, $string2)
    {
        if (!is_string($string1) || !is_string($string2))
            throw new InvalidArgumentException('Arguments must be strings');

        $equal = false;

        if (self::byteLength($string1) === self::byteLength($string2))
        {
            $result = 0;

            for ($byteIndex = 0; $byteIndex < self::byteLength($string1); $byteIndex++)
                $result |= ord($string1[$byteIndex]) ^ ord($string2[$byteIndex]);

            $equal =
                $result === 0;
        }

        return $equal;
    }

}
