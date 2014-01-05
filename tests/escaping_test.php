<?php

require_once __DIR__ . '/../src/escaping.php';


class EscapingTest extends PHPUnit_Framework_TestCase
{

    public function testHTMLEscaping()
    {
        $escaped = Escaping::escapeHTML('plain "\'<>', 'UTF-8');

        $this->assertSame('plain &quot;&#039;&lt;&gt;', $escaped);
    }

    /**
     * @expectedException RuntimeException
     */
    public function testInvalidHTMLInput()
    {
        Escaping::escapeHTML("\xFF", 'UTF-8');
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testInvalidHTMLEncoding()
    {
        Escaping::escapeHTML('foo', 'no-such-encoding');
    }

}
