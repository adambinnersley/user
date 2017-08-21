<?php
namespace UserAuth\Tests;

use DBAL\Database;
use UserAuth\User;
Use PHPUnit\Framework\TestCase;

class UserTest extends TestCase{
    
    protected static $conn;
    protected static $user;
    
    public function setUp() {
        self::$conn = new Database('localhost', 'root', '', 'user_db');
        self::$user = new User(self::$conn);
    }
    
    public function tearDown() {
        unset(self::$conn);
        unset(self::$user);
    }
}
