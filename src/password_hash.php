<?php

require_once __DIR__ . '/random.php';
require_once __DIR__ . '/string_tools.php';


/**
 * Create and verify secure password hashes.
 *
 * The current implementation uses the bcrypt algorithm with the "2y" prefix.
 */
Class PasswordHash
{

    const MAX_PASSWORD_LENGTH = 72;

    const SALT_BYTELENGTH = 16;

    const MIN_COST = 4;

    const MAX_COST = 31;

    const HASH_LENGTH = 60;

    /**
     * @var string
     */
    protected $hash;

    /**
     * @var int
     */
    protected $cost;

    /**
     * @var string
     */
    protected $parameterString;

    /**
     * Create a PasswordHash instance from a plaintext password, a cost factor and an optional salt.
     *
     * @param string      $password   The plaintext password
     * @param int         $cost       The cost factor
     * @param string|null $binarySalt The optional user-provided salt given as a binary string
     *
     * @return PasswordHash The new instance
     *
     * @throws InvalidArgumentException if the password is not a string
     * @throws InvalidArgumentException if the cost factor is not an integer
     * @throws InvalidArgumentException if the salt is neither null nor a string with at least PasswordHash::SALT_BYTELENGTH bytes
     */
    public static function create($password, $cost, $binarySalt = null)
    {
        if (!is_string($password))
            throw new InvalidArgumentException('Password must be a string.');
        if (!is_int($cost))
            throw new InvalidArgumentException('Cost factor must be an integer.');

        if (is_null($binarySalt))
            $binarySalt = Random::generateBytes(self::SALT_BYTELENGTH);
        else
        {
            if (!is_string($binarySalt) || StringTools::byteLength($binarySalt) < self::SALT_BYTELENGTH)
                throw new InvalidArgumentException('Salt must be a binary string with at least ' . self::SALT_BYTELENGTH . ' bytes.');

            $binarySalt = StringTools::byteSubstring($binarySalt, 0, self::SALT_BYTELENGTH);
        }

        $parameterString = self::createParameterString($cost, $binarySalt);
        $hash = self::bcrypt($password, $parameterString);

        return self::resume($hash);
    }

    /**
     * Create a PasswordHash instance from a hash string.
     *
     * @param string $hash
     *
     * @return PasswordHash
     *
     * @throws InvalidArgumentException if the hash is not a string
     */
    public static function resume($hash)
    {
        if (!is_string($hash))
            throw new InvalidArgumentException('Hash must be a string.');

        return new self($hash);
    }

    /**
     * Create a bcrypt parameter string from a cost factor and a binary salt.
     *
     * @param int    $cost The cost factor between PasswordHash::MIN_COST and PasswordHash::MAX_COST
     * @param string $salt The binary salt with exactly PasswordHash::SALT_BYTELENGTH bytes
     *
     * @return string The parameter string
     *
     * @throws InvalidArgumentException if the cost factor is not an integer nor smaller than PasswordHash::MIN_COST or greater than PasswordHash::MAX_COST
     * @throws InvalidArgumentException if the salt is not a string with exactly PasswordHash::SALT_BYTELENGTH bytes
     */
    protected static function createParameterString($cost, $salt)
    {
        if (!is_int($cost) || $cost < self::MIN_COST || $cost > self::MAX_COST)
            throw new InvalidArgumentException('Cost factor must be an integer between ' . self::MIN_COST . ' and ' . self::MAX_COST . '.' );
        if (!is_string($salt) || StringTools::byteLength($salt) !== self::SALT_BYTELENGTH)
            throw new InvalidArgumentException('Salt must be a binary string with exactly ' . self::SALT_BYTELENGTH . ' bytes.');

        $parameterString = sprintf('$2y$%02d$%s', $cost, self::bcryptBase64Encode($salt));

        return $parameterString;
    }

    /**
     * Parse a bcrypt parameter string.
     *
     * @param string $parameterString The bcrypt parameter string with "2y" prefix
     *
     * @return int The cost factor
     *
     * @throws InvalidArgumentException if the input is not a valid bcrypt parameter string
     */
    protected static function parseParameterString($parameterString)
    {
        $parts = null;

        /*
         * Note that bcrypt expects only 128 bit of salt, so the 22nd digit of the bcrypt Base64 representation
         * is effectively limited to ".", "O", "e" and "u". While the current PHP bcrypt implementation accepts
         * all other digits as well and simply maps them to those four, there's no guarantee that other
         * implementations will behave the same way. To prevent the risk of causing problems with the salt,
         * we actually enforce the limitation of the last digit.
         */
        if (!is_string($parameterString) || !preg_match('#\\A\\$2y\\$(?<cost>\\d{2})\\$[./A-Za-z0-9]{21}[.Oeu]\\z#', $parameterString, $parts))
            throw new InvalidArgumentException('Parameter string must be in bcrypt format with "2y" prefix.');

        $cost = intval($parts['cost']);
        if ($cost < self::MIN_COST || $cost > self::MAX_COST)
            throw new InvalidArgumentException('Invalid cost factor in parameter string. Must be between ' . self::MIN_COST . ' and ' . self::MAX_COST . '.' );

        return $cost;
    }

    /**
     * Calculate the bcrypt hash from a plaintext password and a parameter string.
     *
     * @param string $password        The plaintext password
     * @param string $parameterString The bcrypt parameter string with "2y" prefix
     *
     * @return string The bcrypt hash
     *
     * @throws InvalidArgumentException if the password is not a string with a most PasswordHash::MAX_PASSWORD_LENGTH bytes
     * @throws RuntimeException         if the result is not a valid bcrypt hash, or if the parameter string in the hash doesn't match the original one
     */
    protected static function bcrypt($password, $parameterString)
    {
        if (!is_string($password) || StringTools::byteLength($password) > self::MAX_PASSWORD_LENGTH)
            throw new InvalidArgumentException('Password must be a string with at most ' . self::MAX_PASSWORD_LENGTH . ' bytes.');

        // validate parameter string
        self::parseParameterString($parameterString);

        $hash = crypt($password, $parameterString);

        /*
         * Note that crypt() has many different ways of reacting to errors: It may return one of the
         * error strings "*0" and "*1", or it may fall back to either DES-crypt or MD5-crypt, or it
         * may return an invalid hash after padding an undersized salt with "$" characters (PHP bug #62488),
         * or it may repair the last salt digit in case it's outside of its range.
         *
         * The only way to catch all those problems is to carefully validate the return value of crypt():
         *
         * - It must be a string
         * - The length of the hash must be correct.
         * - The parameter string in the resulting hash must be valid, and it must match the original parameter string
         * - The actual hash must only contain valid bcrypt Base64 digits.
         */
        if
        (
            !is_string($hash)
            || StringTools::byteLength($hash) !== self::HASH_LENGTH
            || StringTools::byteSubstring($hash, 0, 29) !== $parameterString
            || !preg_match('#\\A[./A-Za-z0-9]{31}\\z#', StringTools::byteSubstring($hash, 29))
        )
            throw new RuntimeException('Failed to hash password.');

        return $hash;
    }

    /**
     * Encode binary string with the Base64 variant used by bcrypt.
     *
     * Unlike common Base64, bcrypt doesn't use padding. It also has different digits with
     * different values:
     *
     * ./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789
     *
     * @param string $binaryString The binary input string to encode
     *
     * @return string The encoded result
     *
     * @throws InvalidArgumentException if the input is not a string
     */
    protected static function bcryptBase64Encode($binaryString)
    {
        if (!is_string($binaryString))
            throw new InvalidArgumentException('Input must be a string.');

        // use common Base64 and then translate the digits
        $commonBase64Digits = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        $bcryptBase64Digits = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

        $commonBase64 = base64_encode($binaryString);
        return strtr(rtrim($commonBase64, '='), $commonBase64Digits, $bcryptBase64Digits);
    }

    /**
     * Constructor.
     *
     * @param string $hash The bcrypt hash with a "2y" prefix
     *
     * @throws InvalidArgumentException if the input is not a valid bcrypt hash
     */
    protected function __construct($hash)
    {
        if (!is_string($hash) || StringTools::byteLength($hash) !== self::HASH_LENGTH)
            throw new InvalidArgumentException('Hash must be a string with exactly ' . self::HASH_LENGTH . ' bytes.');

        $parameterString = StringTools::byteSubstring($hash, 0, 29);
        $actualHash = StringTools::byteSubstring($hash, 29);

        $cost = self::parseParameterString($parameterString);

        if (!preg_match('#\\A[./A-Za-z0-9]{31}\\z#', $actualHash))
            throw new InvalidArgumentException('Invalid hash.');

        $this->hash = $hash;
        $this->parameterString = $parameterString;
        $this->cost = $cost;
    }

    /**
     * Compare a plaintext password with the stored bcrypt hash.
     *
     * @param string $password The plaintext password with at most PasswordHash::MAX_PASSWORD_LENGTH bytes
     *
     * @return bool Whether the password matches the hash
     *
     * @throws InvalidArgumentException if the password is not a string with at most PasswordHash::MAX_PASSWORD_LENGTH bytes
     */
    public function check($password)
    {
        if (!is_string($password) || StringTools::byteLength($password) > self::MAX_PASSWORD_LENGTH)
            throw new InvalidArgumentException('Password must be a string with at most ' . self::MAX_PASSWORD_LENGTH . ' bytes.');

        $calculatedHash = self::bcrypt($password, $this->parameterString);

        return StringTools::secureCompare($this->hash, $calculatedHash);
    }

    /**
     * @return string
     */
    public function getHash()
    {
        return $this->hash;
    }

    /**
     * @return int
     */
    public function getCost()
    {
        return $this->cost;
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return $this->hash;
    }

}
