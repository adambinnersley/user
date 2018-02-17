<?php
namespace UserAuth\Tests;

use DBAL\Database;
use UserAuth\User;
Use PHPUnit\Framework\TestCase;

class UserTest extends TestCase{
    
    protected static $conn;
    protected static $user;
    
    /**
     * @covers \UserAuth\User::__construct
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
     * @covers \UserAuth\User::changePassword
     * @covers \UserAuth\User::blockStatus
     * @covers \UserAuth\User::isBlocked
     * @covers \UserAuth\User::validatePassword
     * @covers \UserAuth\User::minPasswordStrength
     * @covers \UserAuth\User::getBaseUser
     * @covers \UserAuth\User::getHash
     * @covers \UserAuth\User::deleteAttempts
     * @covers \UserAuth\User::getUserIP
     * @covers \UserAuth\User::getIP
     * @covers \UserAuth\User::__get
     * @covers \UserAuth\User::addAttempt
     * @covers \UserAuth\User::checkCaptcha
     */
    public function testResetPassword(){
        $uid = self::$conn->select(self::$user->table_users, array('email' => 'test@email.com'))['id'];;
        // Successful changePassword
        $this->assertFalse(self::$user->changePassword($uid, 'T3H-1337-P@$$', 'T3H-1337-P@$$2', 'T3H-1337-P@$$2')['error']);
        // Failed changePassword: invalid current password
        $this->assertTrue(self::$user->changePassword($uid, "invalid", 'T3H-1337-P@$$2', 'T3H-1337-P@$$2')['error']);
        // Failed changePassword: incorrect current password
        $this->assertTrue(self::$user->changePassword($uid, "IncorrectPassword1", 'T3H-1337-P@$$2', 'T3H-1337-P@$$2')['error']);
        // Failed changePassword: invalid new password
        $this->assertTrue(self::$user->changePassword($uid, 'T3H-1337-P@$$2', "lamepass", "lamepass")['error']);
        // Failed changePassword: new password and confirmation do not match
        $this->assertTrue(self::$user->changePassword($uid, 'T3H-1337-P@$$2', 'T3H-1337-P@$$3', 'T3H-1337-P@$$4')['error']);
        // Failed changePassword: incorrect UID
        $this->assertTrue(self::$user->changePassword(9999999, 'T3H-1337-P@$$2', 'T3H-1337-P@$$3', 'T3H-1337-P@$$3')['error']);
    }
    
    /**
     * @depends testLogin
     * @covers \UserAuth\User::checkSession
     * @covers \UserAuth\User::__get
     * @covers \UserAuth\User::deleteAttempts
     * @covers \UserAuth\User::getUserIP
     * @covers \UserAuth\User::getIP
     * @covers \UserAuth\User::isBlocked
     */
    public function testCheckSession(){
        // Get the user's (created and logged in as earlier) session hash
        $uid = self::$conn->select(self::$user->table_users, array('email' => 'test@email.com'))['id'];
        $hash = self::$conn->select(self::$user->table_sessions, array('uid' => $uid))['hash'];
        // Successful checkSession
        $this->assertTrue(self::$user->checkSession($hash));
        // Failed checkSession: invalid session hash
        $this->assertFalse(self::$user->checkSession("invalidhash"));
        // Failed checkSession: inexistant session hash
        $this->assertFalse(self::$user->checkSession("aaafda8ea2c65a596c7e089f256b1534f2298000"));
    }
    
    /**
     * @depends testLogin
     * @covers \UserAuth\User::getSessionUID
     * @covers \UserAuth\User::__get
     */
    public function testGetSessionUID(){
        $uid = self::$conn->select(self::$user->table_users, array('email' => 'test@email.com'))['id'];
        $hash = self::$conn->select(self::$user->table_sessions, array('uid' => $uid))['hash'];
        // Successful getSessionUID
        $this->assertEquals($uid, self::$user->getSessionUID($hash));
        // Failed getSessionUID: invalid session hash
        $this->assertFalse(self::$user->getSessionUID("invalidhash"));
        // Failed getSessionUID: inexistant session hash
        $this->assertFalse(self::$user->getSessionUID("aaafda8ea2c65a596c7e089f256b1534f2298000"));
    }
    
    /**
     * @covers \UserAuth\User::isEmailTaken
     * @covers \UserAuth\User::checkEmailExists
     */
    public function testIsEmailTaken(){
        $this->assertTrue(self::$user->isEmailTaken("test@email.com"));
        $this->assertFalse(self::$user->isEmailTaken("unused@email.com"));
        $this->assertArrayHasKey('id', self::$user->checkEmailExists("test@email.com"));
        $this->assertFalse(self::$user->checkEmailExists("unused@email.com"));
    }
    
    /**
     * @covers \UserAuth\User::getUserInfo
     * @covers \UserAuth\User::getUser
     * @covers \UserAuth\User::getUserID
     * @covers \UserAuth\User::getSessionUID
     * @covers \UserAuth\User::getSessionHash
     */
    public function testGetUserInfo(){
        $userInfo = self::$user->getUserInfo(1);
        $this->assertEquals('test@email.com', $userInfo['email']);
    }
    
    /**
     * @covers \UserAuth\User::logout
     * @covers \UserAuth\User::deleteSession
     * @covers \UserAuth\User::__get
     */
    public function testLogout(){
        $uid = self::$conn->select(self::$user->table_users, array('email' => 'test@email.com'))['id'];
        $hash = self::$conn->select(self::$user->table_sessions, array('uid' => $uid))['hash'];
        // Successful logout
        $this->assertTrue(self::$user->logout($hash));
        // Failed logout: invalid session hash
        $this->assertFalse(self::$user->logout("invalidhash"));
        // Failed logout: inexistant session hash
        $this->assertFalse(self::$user->logout("aaafda8ea2c65a596c7e089f256b1534f2298000"));
    }
    
    /**
     * @covers \UserAuth\User::__get
     * @covers \UserAuth\User::addAttempt
     * @covers \UserAuth\User::blockStatus
     * @covers \UserAuth\User::deleteAttempts
     * @covers \UserAuth\User::deleteUser
     * @covers \UserAuth\User::getBaseUser
     * @covers \UserAuth\User::getUserIP
     * @covers \UserAuth\User::getIP
     * @covers \UserAuth\User::isBlocked
     * @covers \UserAuth\User::validatePassword
     */
    public function testDeleteUser() {
        // Empty attempts table
        self::$conn->delete(self::$user->table_attempts, array('id' => array('>=', 1)));
        $uid = self::$conn->select(self::$user->table_users, array('email' => 'test@email.com'))['id'];
        // Failed deleteUser: invalid password
        $this->assertTrue(self::$user->deleteUser($uid, "lamepass")['error']);
        // Failed deleteUser: incorrect password
        $this->assertTrue(self::$user->deleteUser($uid, "IncorrectPassword1")['error']);
        // Successful deleteUser
        $this->assertFalse(self::$user->deleteUser($uid, 'T3H-1337-P@$$2')['error']);
        // Failed deleteUser: incorrect UID
        $this->assertTrue(self::$user->deleteUser(9999999, "IncorrectPassword1")['error']);
    }
    
    /**
     * @covers \UserAuth\User::getUserIP
     * @covers \UserAuth\User::getIP
     */
    public function testGetUserIP(){
        $this->assertEquals('127.0.0.1', self::$user->getUserIP());
    }
}
