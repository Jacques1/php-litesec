<?php

/**
 * Escaping raw values so that they can be used as data in a particular context.
 */
class Escaping
{

    /**
     * The list of character encodings supported by escapeHTML().
     *
     * It matches the supported encodings used by htmlspecialchars() in PHP 5.3.7.
     *
     * @var array
     */
    protected static $supportedHtmlEncodings = array(
        'ISO-8859-1'
        , 'ISO8859-1'
        , 'ISO-8859-15'
        , 'ISO8859-15'
        , 'utf-8'
        , 'cp1252'
        , 'Windows-1252'
        , '1252'
        , 'BIG5'
        , '950'
        , 'GB2312'
        , '936'
        , 'BIG5-HKSCS'
        , 'Shift_JIS'
        , 'SJIS'
        , '932'
        , 'EUCJP'
        , 'EUC-JP'
        , 'KOI8-R'
        , 'koi8-ru'
        , 'koi8r'
        , 'cp1251'
        , 'Windows-1251'
        , 'win-1251'
        , 'iso8859-5'
        , 'iso-8859-5'
        , 'cp866'
        , '866'
        , 'ibm866'
        , 'MacRoman'
    );

    /**
     * Escape a string so that it can be used as data in an HTML context.
     *
     * This method will replace ampersands, single and double quotes and angle brackets with
     * their corresponding HTML entities. A single quote will be replaced with &#039;
     * rather than &apos;, because the latter is not compatible with HTML 4.
     *
     * @param string $rawInput The input string
     * @param string $encoding The character encoding to be used
     *
     * @return string The escaped string
     *
     * @throws InvalidArgumentException if the character encoding is not a string
     * @throws InvalidArgumentException if the encoding is not supported
     * @throws RuntimeException         if the escaped output is empty but the input was not (this indicates invalid characters)
     */
    public static function escapeHTML($rawInput, $encoding)
    {
        if (!is_string($encoding))
            throw new InvalidArgumentException('Character encoding must be a string.');

        /*
         * When htmlspecialchars() encounters an invalid encoding argument, it will fall back
         * to a default encoding (either ISO-8859-1 or UTF-8, depending on the PHP version).
         * This is downright dangerous, because if the escaping procedure doesn't use the
         * intended encoding, it's not guranteed that it will actually recognize the characters
         * and escape them correctly. For example, trying to escape a double quote in UTF-7
         * ("+ACI-") will leave the original input unmodified. PHP merely emits a notice that
         * it doesn't support UTF-7 and has used the default encoding instead.
         *
         * To prevent this kind of vulnerability, any unsupported encoding should cause a fatal error.
         */
        $validEncoding = false;
        foreach (self::$supportedHtmlEncodings as $supportedEncoding)
        {
            if (strcasecmp($encoding, $supportedEncoding) === 0)
            {
                $validEncoding = true;
                break;
            }
        }
        if (!$validEncoding)
            throw new InvalidArgumentException('Unsupported character encoding.');

        // set the ENT_HTML401 flag to escape single quotes as &#039;
        $escaped = htmlspecialchars($rawInput, ENT_QUOTES | ENT_HTML401, $encoding);

        if (!$escaped && $rawInput)
            throw new RuntimeException('Could not process input string.');

        return $escaped;
    }

}
