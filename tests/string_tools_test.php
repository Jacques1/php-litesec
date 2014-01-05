<?php

require_once __DIR__ . '/../src/string_tools.php';


class ToolsTest extends PHPUnit_Framework_TestCase
{

    public function testSecureStringCompare()
    {
        $string_1 = 'foobar';
        $string_2 = 'foobarfoo';

        $this->assertTrue(StringTools::secureCompare($string_1, $string_1));
        $this->assertTrue(StringTools::secureCompare('', ''));

        $this->assertFalse(StringTools::secureCompare($string_1, $string_2));
        $this->assertFalse(StringTools::secureCompare($string_2, $string_1));

        $this->assertFalse(StringTools::secureCompare($string_1, ''));
        $this->assertFalse(StringTools::secureCompare('', $string_1));
    }

    public function testByteLength()
    {
        $asciiString = 'foobar';
        $binaryString = "\xFF\x00\xFF";

        $this->assertSame(6, StringTools::byteLength($asciiString));
        $this->assertSame(3, StringTools::byteLength($binaryString));
    }

    public function testByteSubstring()
    {
        $asciiString = 'foobar';
        $binaryString = "\xFF\x00\xFF";

        $this->assertSame('foo', StringTools::byteSubstring($asciiString, 0, 3));
        $this->assertSame("\x00", StringTools::byteSubstring($binaryString, 1, 1));
    }

}
