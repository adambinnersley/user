<?php
namespace UserAuth\Tests;

use DBAL\Database;
use UserAuth\User;
Use PHPUnit\Framework\TestCase;

class UserTest extends TestCase{
    
    protected static $conn;
    protected static $user;
    
    /**
     * @covers \UserAuth\User
     * @covers \UserAuth\User::setLanguageFile
     */
    public static function setUpBeforeClass() {
        self::$conn = new Database($GLOBALS['HOSTNAME'], $GLOBALS['USERNAME'], $GLOBALS['PASSWORD'], $GLOBALS['DATABASE'], false, false, true, $GLOBALS['DRIVER']);
        self::$conn->query(file_get_contents(dirname(dirname(__FILE__)).'/database/database_mysql.sql'));
        self::$user = new User(self::$conn);
    }
    
    /**
     * @covers \UserAuth\User::__construct
     * @covers \UserAuth\User::setLanguageFile
     * @covers \UserAuth\User::__get
     * @covers \UserAuth\User::__set
     */
    public function testGettersAndSetters(){
        $this->assertEquals(3, self::$user->password_min_score);
        self::$user->password_min_score = 4;
        $this->assertEquals(4, self::$user->password_min_score);
        $this->assertFalse(self::$user->some_random_var);
    }
    
    /**
     * @covers \UserAuth\User::__construct
     * @covers \UserAuth\User::setLanguageFile
     */
    public function testSetLang(){
        $setLang = self::$user->setLanguageFile(dirname(dirname(__FILE__))."languages/en_GB.php");
        $this->assertObjectHasAttribute('lang', $setLang);
        $this->assertArrayHasKey('user_blocked', self::$user->lang);
        $this->assertEquals("Email address is too long.", self::$user->lang['email_long']);
    }
    
    /**
     * @covers \UserAuth\User::register
     * @covers \UserAuth\User::blockStatus
     * @covers \UserAuth\User::isBlocked
     * @covers \UserAuth\User::validateEmailPassword
     * @covers \UserAuth\User::validateEmail
     * @covers \UserAuth\User::validatePassword
     * @covers \UserAuth\User::minPasswordStrength
     * @covers \UserAuth\User::isEmailTaken
     * @covers \UserAuth\User::addAttempt
     * @covers \UserAuth\User::addUser
     * @covers \UserAuth\User::getHash
     * @covers \UserAuth\User::deleteAttempts
     * @covers \UserAuth\User::getUserIP
     * @covers \UserAuth\User::getIP
     */
    public function testRegister(){
        // Successful registration
        $this->assertFalse(self::$user->register('test@email.com', 'T3H-1337-P@$$', 'T3H-1337-P@$$')['error']);
        // Failed registration: same email
        $this->assertTrue(self::$user->register('test@email.com', 'T3H-1337-P@$$', 'T3H-1337-P@$$')['error']);
        // Failed registration: invalid email address
        $this->assertTrue(self::$user->register('InvalidEmail', 'T3H-1337-P@$$', 'T3H-1337-P@$$')['error']);
        // Failed registration: invalid password
        $this->assertTrue(self::$user->register('test2@email.com', 'lamepass', 'lamepass')['error']);
    }
    
    /**
     * @covers \UserAuth\User::__set
     * @covers \UserAuth\User::activate
     * @covers \UserAuth\User::register
     * @covers \UserAuth\User::blockStatus
     * @covers \UserAuth\User::isBlocked
     * @covers \UserAuth\User::validateEmailPassword
     * @covers \UserAuth\User::validateEmail
     * @covers \UserAuth\User::validatePassword
     * @covers \UserAuth\User::minPasswordStrength
     * @covers \UserAuth\User::isEmailTaken
     * @covers \UserAuth\User::addAttempt
     * @covers \UserAuth\User::deleteRequest
     * @covers \UserAuth\User::addUser
     * @covers \UserAuth\User::getHash
     * @covers \UserAuth\User::getBaseUser
     */
    public function testActivate(){
        $this->markTestIncomplete();
    }
    
    /**
     * @covers \UserAuth\User::resetPass
     * @covers \UserAuth\User::blockStatus
     * @covers \UserAuth\User::isBlocked
     * @covers \UserAuth\User::validatePassword
     * @covers \UserAuth\User::minPasswordStrength
     * @covers \UserAuth\User::getBaseUser
     * @covers \UserAuth\User::getHash
     */
    public function testResetPassword(){
        $this->markTestIncomplete();
    }
    
    /**
     * @covers \UserAuth\User::login
     * @covers \UserAuth\User::blockStatus
     * @covers \UserAuth\User::isBlocked
     * @covers \UserAuth\User::validateEmailPassword
     * @covers \UserAuth\User::validateEmail
     * @covers \UserAuth\User::validatePassword
     * @covers \UserAuth\User::checkUsernamePassword
     * @covers \UserAuth\User::getBaseUser
     * @covers \UserAuth\User::addAttempt
     * @covers \UserAuth\User::addSession
     * @covers \UserAuth\User::setLastLogin
     * @covers \UserAuth\User::deleteAttempts
     * @covers \UserAuth\User::getUserIP
     * @covers \UserAuth\User::getIP
     */
    public function testLogin(){
        // Successful login
        $this->assertFalse(self::$user->login("test@email.com", 'T3H-1337-P@$$')['error']);
        // Failed login: incorrect email
        $this->assertTrue(self::$user->login("incorrect@email.com", "IncorrectPassword1")['error']);
        // Failed login: incorrect password
        $this->assertTrue(self::$user->login("test@email.com", "IncorrectPassword1")['error']);
    }
    
    /**
     * @covers \UserAuth\User::getUserInfo
     * @covers \UserAuth\User::getUser
     * @covers \UserAuth\User::getUserID
     * @covers \UserAuth\User::getSessionUID
     * @covers \UserAuth\User::getSessionHash
     */
    public function testGetUserInfo(){
        $this->markTestIncomplete();
    }
    
    /**
     * @covers \UserAuth\User::logout
     * @covers \UserAuth\User::deleteSession
     */
    public function testLogout(){
        $this->markTestIncomplete();
    }
    
    /**
     * @covers \UserAuth\User::getUserIP
     * @covers \UserAuth\User::getIP
     */
    public function testGetUserIP(){
        $this->markTestIncomplete();
    }
}
