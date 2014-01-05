<?php

require_once __DIR__ . '/../src/password_hash.php';


class PasswordHashTest extends PHPUnit_Framework_TestCase
{

    public function testCreate()
    {
        $testPassword = pack('H*', '69be40a7a70f3b680e5f25c5ff07464133dd0ac808c0e41feada7c278643b751d75b6d27dc182aa4265c988ee22b27f5227dcda2c52e0ccae335dfefc0b1e79e70704a7cfd345648');
        $salt = pack('H*', 'f76b16db42bf3b237b81497395806f1a');
        $cost = 10;
        $expectedHash = '$2y$10$70qU0yI9MwL5eSjxjW/tEek2oVr9e1yKLNJncrYHXaT5DbjA4WDHi';

        $passwordHash = PasswordHash::create($testPassword, $cost, $salt);

        $this->assertSame($expectedHash, $passwordHash->getHash());
        $this->assertSame(10, $passwordHash->getCost());
    }

    public function testResume()
    {
        $testHash = '$2y$10$70qU0yI9MwL5eSjxjW/tEek2oVr9e1yKLNJncrYHXaT5DbjA4WDHi';

        $passwordHash = PasswordHash::resume($testHash);

        $this->assertSame($testHash, $passwordHash->getHash());
        $this->assertSame(10, $passwordHash->getCost());
    }

    public function testCheck()
    {
        $testHash = '$2y$10$70qU0yI9MwL5eSjxjW/tEek2oVr9e1yKLNJncrYHXaT5DbjA4WDHi';
        $correctPassword = pack('H*', '69be40a7a70f3b680e5f25c5ff07464133dd0ac808c0e41feada7c278643b751d75b6d27dc182aa4265c988ee22b27f5227dcda2c52e0ccae335dfefc0b1e79e70704a7cfd345648');
        $wrongPassword = $correctPassword;
        $wrongPassword[4] = "\xab";

        $passwordHash = PasswordHash::resume($testHash);

        $this->assertTrue($passwordHash->check($correctPassword));
        $this->assertFalse($passwordHash->check($wrongPassword));
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testPasswordLimit()
    {
        $testPassword = str_repeat("\xab", 73);

        PasswordHash::create($testPassword, 10);
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testCostTooLow()
    {
        PasswordHash::create('foo', 3);
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testCostTooHigh()
    {
        PasswordHash::create('foo', 32);
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testInvalidPrefix()
    {
        $hash = '$2a$10$70qU0yI9MwL5eSjxjW/tEek2oVr9e1yKLNJncrYHXaT5DbjA4WDHi';    // note "2a" instead of "2y"

        PasswordHash::resume($hash);
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testInvalidHashCost()
    {
        $hash = '$2y$32$70qU0yI9MwL5eSjxjW/tEek2oVr9e1yKLNJncrYHXaT5DbjA4WDHi';    // note "32"

        PasswordHash::resume($hash);
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testInvalidSaltDigit()
    {
        $hash = '$2y$10$70qU0yI9M+L5eSjxjW/tEek2oVr9e1yKLNJncrYHXaT5DbjA4WDHi';    // note "+"

        PasswordHash::resume($hash);
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testInvalidSaltEnding()
    {
        $hash = '$2y$10$70qU0yI9MwL5eSjxjW/tExk2oVr9e1yKLNJncrYHXaT5DbjA4WDHi';    // note "x"

        PasswordHash::resume($hash);
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testInvalidHashDigit()
    {
        $hash = '$2y$10$70qU0yI9MwL5eSjxjW/tEek2oVr9e1yKLNJncr+HXaT5DbjA4WDHi';    // note "+"

        PasswordHash::resume($hash);
    }

}
