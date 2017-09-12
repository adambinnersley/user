<?php
/**
 * DBAL User class
 * @author Adam Binnersley
 * @version 1.0.0
 * @requires PHP 5.4.0 or greater
 */
namespace UserAuth;

use DBAL\Database;
use ZxcvbnPhp\Zxcvbn as PasswordStrength;

class User implements UserInterface{
    protected static $db;
    protected static $lang;
    
    protected $userID;
    protected $userInfo;
    
    protected $table_users = 'users';
    protected $table_sessions = 'sessions';
    protected $table_requests = 'requests';
    protected $table_attempts = 'attempts';
    
    protected $activation_page = 'activate';
    protected $password_reset_page = 'reset';
    
    protected $attack_mitigation_time = '+30 minutes';
    protected $attempts_before_ban = 30;
    protected $attempts_before_verify = 5;
    protected $use_banlist = true;
    
    public $site_timezone = 'Europe/London';
    
    public $cookie_name = 'authID';
    public $cookie_forget = '+30 minutes';
    public $cookie_remember = 31536000;
    
    protected $password_cost = 11;
    protected $password_min_score = 3;
    
    protected $request_key_expiration = '+10 minutes';
    
    public $send_activation_email = true;
    public $send_reset_email = true;
    
    public $emailFrom = 'user@example.com';
    public $emailFromName = 'User Account';

    /**
     * Initiates essential objects
     * @param Database $db
     * @param string $language
     */
    public function __construct(Database $db, $language = "en_GB") {
        self::$db = $db;
        
        require "languages/{$language}.php";
        self::$lang = $lang;

        date_default_timezone_set($this->site_timezone);
    }
    
    /**
     * Getter Will retrieve set variables
     * @param string $name This should be the string value name
     * @return mixed This will be the string value if it exists
     */
    public function __get($name) {
        return $this->$name;
    }
    
    /**
     * Setter Will set class variables
     * @param string $name This should be the variable name
     * @param mixed $value This should be the variable value you wish to set it to
     */
    public function __set($name, $value) {
        if(defined($this->$name)){
            $this->$name = $value;
        }
    }

    /**
     * Logs a user in
     * @param string $email
     * @param string $password
     * @param boolean $remember
     * @param string $captcha = NULL
     * @return array $return
     */
    public function login($email, $password, $remember = true, $captcha = NULL) {
        $return = array();
        $return['error'] = true;
        
        $block_status = $this->blockStatus($captcha);
        if($block_status !== false) {
            $return['message'] = $block_status;
            return $return;
        }

        $validateInfo = $this->validateEmailPassword($email, $password);
        if($validateInfo !== false) {
            $return['message'] = $validateInfo;
            return $return;
        }

        $user = $this->checkUsernamePassword($email, $password);
        if (empty($user)) {
            $this->addAttempt();
            $return['message'] = self::$lang["email_password_incorrect"];
            return $return;
        }

        if ($user['isactive'] != 1) {
            $this->addAttempt();
            $return['message'] = self::$lang["account_inactive"];
            return $return;
        }
        
        $sessiondata = $this->addSession($user['id'], $remember);
        if ($sessiondata === false) {
            $return['message'] = self::$lang["system_error"] . " #01";
            return $return;
        }

        $return['error'] = false;
        $return['message'] = self::$lang["logged_in"];
        $return['hash'] = $sessiondata['hash'];
        $return['expire'] = $sessiondata['expiretime'];
        $return['cookie_name'] = $this->cookie_name;
        return $return;
    }
    
    /**
     * Checks to see if the username and password match that whats in the database
     * @param string $username This should be the users email address
     * @param string $password This should be the users password
     * @return array|false If the information is correct the users information will be returned else will return false
     */
    protected function checkUsernamePassword($username, $password) {
        $data = self::$db->select($this->table_users, array('email' => strtolower($username)));
        if(empty($data)){
            return false;
        }
        if(password_verify($password, $data['password']) === true){
            unset($data['password']);
            return $data;
        }
        return false;
    }
    
    /**
     * 
     * @param string $email
     * @return array|false
     */
    protected function checkEmailExists($email){
        return self::$db->select($this->table_users, array('email' => $email), array('id'));
    }
    
    /**
    * Creates a new user, adds them to database
    * @param string $email
    * @param string $password
    * @param string $repeatpassword
    * @param array  $params
    * @param string $captcha = NULL
    * @param bool $sendmail = NULL
    * @return array $return
    */
    public function register($email, $password, $repeatpassword, $params = array(), $captcha = NULL, $sendmail = NULL) {
        $return = array();
        $return['error'] = true;
        
        $block_status = $this->blockStatus($captcha);
        if($block_status !== false) {
            $return['message'] = $block_status;
            return $return;
        }

        if ($password !== $repeatpassword) {
            $return['message'] = self::$lang["password_nomatch"];
            return $return;
        }

        $validateInfo = $this->validateEmailPassword($email, $password);
        if($validateInfo !== false) {
            $return['message'] = $validateInfo;
            return $return;
        }

        $strength = $this->minPasswordStrength($password);
        if($strength !== false){
            $return['message'] = $strength['message'];
            return $return;
        }

        if ($this->isEmailTaken($email)) {
            $this->addAttempt();
            $return['message'] = self::$lang["email_taken"];
            return $return;
        }

        $addUser = $this->addUser($email, $password, $params, $sendmail);
        if ($addUser['error'] != 0) {
            $return['message'] = $addUser['message'];
            return $return;
        }

        $return['error'] = false;
        $return['message'] = ($sendmail === true ? self::$lang["register_success"] : self::$lang['register_success_emailmessage_suppressed']);
        return $return;
    }
    
    /**
    * Activates a user's account
    * @param string $key
    * @return array $return
    */
    public function activate($key) {
        $return = array();
        $return['error'] = true;
        if($this->isBlocked() == "block"){
            $return['message'] = self::$lang["user_blocked"];

            return $return;
        }
        if(strlen($key) !== 20){
            $this->addAttempt();
            $return['message'] = self::$lang["activationkey_invalid"];
            return $return;
        }

        $request = $this->getRequest($key, "activation");
        if($request['error'] == 1){
            $return['message'] = $request['message'];
            return $return;
        }

        if($this->getBaseUser($request['uid'])['isactive'] == 1){
            $this->addAttempt();
            $this->deleteRequest($request['id']);
            $return['message'] = self::$lang["system_error"] . " #02";
            return $return;
        }
        
        self::$db->update($this->table_users, array('isactive' => 1), array('id' => $request['uid']));
        $this->deleteRequest($request['id']);

        $return['error'] = false;
        $return['message'] = self::$lang["account_activated"];

        return $return;
    }
    
    /**
    * Creates a reset key for an email address and sends email
    * @param string $email
    * @return array $return
    */
    public function requestReset($email, $sendmail = NULL){
        $return = array();
        $return['error'] = true;

        if($this->isBlocked() == "block"){
            $return['message'] = self::$lang["user_blocked"];
            return $return;
        }

        $validateEmail = $this->validateEmail($email);
        if($validateEmail['error'] == 1){
            $return['message'] = $validateEmail['message'];
            return $return;
        }

        $row = $this->checkEmailExists($email);
	if(empty($row)){
            $this->addAttempt();
            $return['message'] = self::$lang["email_incorrect"];
            return $return;
        }

        $addRequest = $this->addRequest($row['id'], $email, "reset", $sendmail);
        if($addRequest['error'] == 1){
            $this->addAttempt();
            $return['message'] = $addRequest['message'];
            return $return;
        }

        $return['error'] = false;
        $return['message'] = ($sendmail === true ? self::$lang["reset_requested"] : self::$lang['reset_requested_emailmessage_suppressed']);
        return $return;
    }
    
    /**
    * Logs out the session, identified by hash
    * @param string $hash
    * @return boolean
    */
    public function logout($hash){
        if(strlen($hash) != 40){
            return false;
        }
        return $this->deleteSession($hash);
    }
    
    /**
    * Hashes provided password with Bcrypt
    * @param string $password
    * @return string
    */
    public function getHash($password){
        return password_hash($password, PASSWORD_DEFAULT, ['cost' => $this->password_cost]);
    }
    
    /**
    * Gets UID for a given email address and returns an array
    * @param string $email
    * @return int|false 
    */
    public function getUID($email){
        if(is_int($this->userID)){
            return $this->userID;
        }
        else{
            $row = $this->checkEmailExists($email);
            if(empty($row)){
                return false;
            }
            return $row['id'];
        }
    }

    /**
    * Creates a session for a specified user id
    * @param int $uid
    * @param boolean $remember
    * @return array $data
    */
    protected function addSession($uid, $remember){
        if(!$this->getBaseUser($uid)){
            return false;
        }
        $data = array();
        $data['hash'] = sha1(SITE_KEY . microtime());
        $this->deleteExistingSessions($uid);
        if($remember === true){
            $data['expire'] = date("Y-m-d H:i:s", strtotime($this->cookie_remember));
            $data['expiretime'] = strtotime($data['expire']);
        }
        else{
            $data['expire'] = date("Y-m-d H:i:s", strtotime($this->cookie_forget));
            $data['expiretime'] = 0;
        }

        if(!self::$db->insert($this->table_sessions, array('uid' => $uid, 'hash' => $data['hash'], 'expiredate' => $data['expire'], 'ip' => $this->getIp(), 'agent' => (isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : ''), 'cookie_crc' => sha1($data['hash'] . SITE_KEY)))){
            return false;
        }
        
        setcookie($this->cookie_name, $data['hash'], $data['expire'], '/');
        $_COOKIE[$this->cookie_name] = $data['hash'];

        $data['expire'] = strtotime($data['expire']);
        return $data;
    }
    
    /**
    * Removes all existing sessions for a given UID
    * @param int $uid
    * @return boolean
    */
    protected function deleteExistingSessions($uid){
        return self::$db->delete($this->table_sessions, array('uid' => $uid));
    }
    
    /**
    * Removes a session based on hash
    * @param string $hash
    * @return boolean
    */
    protected function deleteSession($hash){
        return self::$db->delete($this->table_sessions, array('hash' => $hash));
    }

    /**
    * Function to check if a session is valid
    * @param string $hash
    * @return boolean
    */
    protected function checkSession($hash){
        if($this->isBlocked() == "block"){
            return false;
        }

        if(strlen($hash) != 40){
            return false;
        }

        $row = self::$db->select($this->table_sessions, array('hash' => $hash));
        if(empty($row)){
            return false;
        }

        if(strtotime(date("Y-m-d H:i:s")) > strtotime($row['expiredate'])){
            $this->deleteExistingSessions($row['uid']);
            return false;
        }

        if($this->getIp() != $row['ip']){
            return false;
        }

        if($row['cookie_crc'] == sha1($hash . SITE_KEY)){
            return true;
        }

        return false;
    }
    
    /**
    * Retrieves the UID associated with a given session hash
    * @param string $hash
    * @return int|false
    */
    public function getSessionUID($hash){
        $row = self::$db->select($this->table_sessions, array('hash' => $hash) , array('uid'));
        if(empty($row)){
            return false;
        }
        return $row['uid'];
    }
    
     /**
    * Checks if an email is already in use
    * @param string $email
    * @return boolean
    */
    public function isEmailTaken($email){
        if(self::$db->count($this->table_users, array('email' => $email)) == 0){
            return false;
        }
        return true;
    }
    
    /**
    * Adds a new user to database
    * @param string $email      -- email
    * @param string $password   -- password
    * @param array $params      -- additional params
    * @param boolean|null $sendmail
    * @return int|array 
    */
    protected function addUser($email, $password, $params = array(), &$sendmail){
        $return = array();
        $return['error'] = true;

        $safeemail = htmlentities(strtolower($email));
        $requiredParams = array($safeemail, $this->getHash($password), ($sendmail ? 0 : 1));
        if(is_array($params)&& count($params) > 0){
            $setParams = array_merge($requiredParams, $params);
        }
        else{$setParams = $requiredParams;}

        if(!self::$db->insert($this->table_users, $setParams)){
            $return['message'] = self::$lang["system_error"] . " #03";
            return $return;
        }
        elseif($sendmail){
            $this->addRequest(self::$db->lastInsertId(), $email, "activation", $sendmail);
        }

        $return['error'] = false;
        return $return;
    }
    
    /**
    * Gets basic user data for a given UID and returns an array
    * @param int $uid
    * @return array $data
    */
    protected function getBaseUser($uid){
        $data = self::$db->select($this->table_users, array('id' => $uid), array('email', 'password', 'isactive'));
        if(empty($data)){
            return false;
        }
        
        $data['uid'] = $uid;
        return $data;
    }
    
    /**
    * Gets public user data for a given UID and returns an array, password is not returned
    * @param int|false $uid This should be the user ID of the person you are getting the information for
    * @return array|false If information exists for the user will return an array else will return false
    */
    public function getUser($uid){
        if(is_integer($uid)){
            $data = self::$db->select($this->table_users, array('id' => $uid));
            if(empty($data)){
                return false;
            }
            $data['uid'] = $uid;
            unset($data['password']);
            return $data;
        }
        return false;
    }
    
    /**
    * Allows a user to delete their account
    * @param int $uid
    * @param string $password
    * @param string $captcha = NULL
    * @return array $return
    */
    public function deleteUser($uid, $password, $captcha = NULL){
        $return = array();
        $return['error'] = true;

        $block_status = $this->blockStatus($captcha);
        if($block_status !== false) {
            $return['message'] = $block_status;
            return $return;
        }

        $validatePassword = $this->validatePassword($password);
        if($validatePassword['error'] == 1){
            $this->addAttempt();
            $return['message'] = $validatePassword['message'];
            return $return;
        }

        $user = $this->getBaseUser($uid);
        if(!password_verify($password, $user['password'])){
            $this->addAttempt();
            $return['message'] = self::$lang["password_incorrect"];
            return $return;
        }

        if(!self::$db->delete($this->table_users, array('id' => $uid)) || !self::$db->delete($this->table_sessions, array('uid' => $uid)) || !self::$db->delete($this->table_requests, array('uid' => $uid))){
            $return['message'] = self::$lang["system_error"] . " #05";
            return $return;
        }

        $return['error'] = false;
        $return['message'] = self::$lang["account_deleted"];

        return $return;
    }
    
    /**
    * Creates an activation entry and sends email to user
    * @param int $uid
    * @param string $email
    * @param string $type
    * @param boolean|null $sendmail = NULL
    * @return boolean
    */
    protected function addRequest($uid, $email, $type, &$sendmail){
        $return = array();
        $return['error'] = true;

        if($type != "activation" && $type != "reset"){
            $return['message'] = self::$lang["system_error"] . " #08";
            return $return;
        }

        if($sendmail === NULL){
            $sendmail = true;
            if(($type == "reset" && $this->send_reset_email !== true) || ($type == "activation" && $this->send_activation_email !== true)){
                $sendmail = false;
                $return['error'] = false;
                return $return;
            }
        }

        $row = self::$db->select($this->table_requests, array('uid' => $uid, 'type' => $type), array('id', 'expire'));
        if(!empty($row)){
            if(strtotime(date("Y-m-d H:i:s")) < strtotime($row['expire'])){
                $return['message'] = self::$lang["reset_exists"];
                return $return;
            }
            $this->deleteRequest($row['id']);
        }

        if($type == "activation" && $this->getBaseUser($uid)['isactive'] == 1){
            $return['message'] = self::$lang["already_activated"];
            return $return;
        }
        
        $key = $this->getRandomKey(20);
        if(!self::$db->insert($this->table_requests, array('uid' => $uid, 'rkey' => $key, 'expire' => date("Y-m-d H:i:s", strtotime($this->request_key_expiration)), 'type' => $type))){
            $return['message'] = self::$lang["system_error"] . " #09";
            return $return;
        }

        if($sendmail === true){
            if($type == "activation"){
                $mailsent = sendEmail($email, sprintf(self::$lang['email_activation_subject'], SITE_NAME), sprintf(self::$lang['email_activation_body'], SITE_URL, $this->activation_page, $key), sprintf(self::$lang['email_activation_altbody'], SITE_URL, $this->activation_page, $key), $this->emailFrom, $this->emailFromName);
            }else{
                $mailsent = sendEmail($email, sprintf(self::$lang['email_reset_subject'], SITE_NAME), sprintf(self::$lang['email_reset_body'], SITE_URL, $this->password_reset_page, $key), sprintf(self::$lang['email_reset_altbody'], SITE_URL, $this->password_reset_page, $key), $this->emailFrom, $this->emailFromName);
            }
            if(!$mailsent){
                $this->deleteRequest(self::$db->lastInsertId());
                $return['message'] = self::$lang["system_error"] . " #10";
                return $return;
            }
        }
        $return['error'] = false;

        return $return;
    }
    
    /**
    * Returns request data if key is valid
    * @param string $key
    * @param string $type
    * @return array $return
    */
    public function getRequest($key, $type){
        $return = array();
        $return['error'] = true;
        
        $request = self::$db->select($this->table_requests, array('rkey' => $key, 'type' => $type), array('id', 'uid', 'expire'));
        if(empty($request)){
            $this->addAttempt();
            $return['message'] = self::$lang[$type."key_incorrect"];
            return $request;
        }
        
        if(strtotime(date("Y-m-d H:i:s")) > strtotime($request['expire'])){
            $this->addAttempt();
            $this->deleteRequest($request['id']);
            $return['message'] = self::$lang[$type."key_expired"];
            return $request;
        }
        
        $return['error'] = false;
        $return['id'] = $request['id'];
        $return['uid'] = $request['uid'];
        return $return;
    }
    
    /**
    * Deletes request from database
    * @param int $id
    * @return boolean
    */
    protected function deleteRequest($id){
        return self::$db->delete($this->table_requests, array('id' => $id));
    }
    
    /**
    * Verifies that a password is valid and respects security requirements
    * @param string $password
    * @return array $return
    */
    protected function validatePassword($password){
        $return = array();
        $return['error'] = true;
        if(strlen($password) < 5){
            $return['message'] = self::$lang["password_short"];
            return $return;
        }

        $return['error'] = false;
        return $return;
    }
    
    /**
     * checks to see if the given password meets the minimum strength requirements
     * @param string $password This should be the password you are checking for strength
     * @return array|boolean If the password doe not meet the minimum requirements will return an array containing the error message else will return false
     */
    protected function minPasswordStrength($password){
        $return = array();
        $strength = new PasswordStrength();
        if($strength->passwordStrength($password)['score'] < intval($this->password_min_score)){
            $return['message'] = self::$lang['password_weak'];
            return $return;
        }
        return false;
    }
    
    /**
    * Verifies that an email is valid
    * @param string $email
    * @return array $return
    */
    protected function validateEmail($email){
        $return = array();
        $return['error'] = true;

        if(strlen($email) < 5){
            $return['message'] = self::$lang["email_short"];
            return $return;
        }elseif(strlen($email) > 100){
            $return['message'] = self::$lang["email_long"];
            return $return;
        }elseif(!filter_var($email, FILTER_VALIDATE_EMAIL)){
            $return['message'] = self::$lang["email_invalid"];
            return $return;
        }

        if($this->use_banlist === true){
            $bannedEmails = json_decode(file_get_contents(__DIR__ . "/files/domains.json"));

            if(in_array(strtolower(explode('@', $email)[1]), $bannedEmails)){
                $return['message'] = self::$lang["email_banned"];
                return $return;
            }
        }

        $return['error'] = false;
        return $return;
    }
    
    /**
    * Allows a user to reset their password after requesting a reset key.
    * @param string $key
    * @param string $password
    * @param string $repeatpassword
    * @param string $captcha = NULL
    * @return array $return
    */
    public function resetPass($key, $password, $repeatpassword, $captcha = NULL){
        $return = array();
        $return['error'] = true;
        
        $block_status = $this->blockStatus($captcha);
        if($block_status !== false) {
            $return['message'] = $block_status;
            return $return;
        }

        if(strlen($key) != 20){
            $return['message'] = self::$lang["resetkey_invalid"];
            return $return;
        }

        $validatePassword = $this->validatePassword($password);
        if($validatePassword['error'] == 1){
            $return['message'] = $validatePassword['message'];
            return $return;
        }

        if($password !== $repeatpassword){
            $return['message'] = self::$lang["newpassword_nomatch"];
            return $return;
        }

        $strength = $this->minPasswordStrength($password);
        if($strength !== false){
            $return['message'] = $strength['message'];
            return $return;
        }
	    
        $data = $this->getRequest($key, "reset");
        if($data['error'] == 1){
            $return['message'] = $data['message'];
            return $return;
        }

        $user = $this->getBaseUser($data['uid']);
        if(!$user){
            $this->addAttempt();
            $this->deleteRequest($data['id']);
            $return['message'] = self::$lang["system_error"] . " #11";

            return $return;
        }

        if(password_verify($password, $user['password'])){
            $this->addAttempt();
            $return['message'] = self::$lang["newpassword_match"];
            return $return;
        }

        if(self::$db->update($this->table_users, array('password' => $this->getHash($password)), array('id' => $data['uid'])) === false){
            $return['message'] = self::$lang["system_error"] . " #12";
            return $return;
        }

        $this->deleteRequest($data['id']);
        $return['error'] = false;
        $return['message'] = self::$lang["password_reset"];
        return $return;
    }
    
    /**
    * Recreates activation email for a given email and sends
    * @param string $email
    * @return array $return
    */
    public function resendActivation($email){
        $return = array();
        $return['error'] = true;

        if($this->isBlocked() == "block"){
            $return['message'] = self::$lang["user_blocked"];
            return $return;
        }

        $validateEmail = $this->validateEmail($email);
        if($validateEmail['error'] == 1){
            $return['message'] = $validateEmail['message'];
            return $return;
        }

        $row = $this->checkEmailExists($email);
        if(empty($row)){
            $this->addAttempt();
            $return['message'] = self::$lang["email_incorrect"];
            return $return;
        }

        if($this->getBaseUser($row['id'])['isactive'] == 1){
            $this->addAttempt();
            $return['message'] = self::$lang["already_activated"];
            return $return;
        }

        $addRequest = $this->addRequest($row['id'], $email, "activation", NULL);
        if($addRequest['error'] == 1){
            $this->addAttempt();
            $return['message'] = $addRequest['message'];
            return $return;
        }

        $return['error'] = false;
        $return['message'] = self::$lang["activation_sent"];
        return $return;
    }
    
    /**
    * Changes a user's password
    * @param int $uid
    * @param string $currpass
    * @param string $newpass
    * @param string $repeatnewpass
    * @param string $captcha = NULL
    * @return array $return
    */
    public function changePassword($uid, $currpass, $newpass, $repeatnewpass, $captcha = NULL){
        $return = array();
        $return['error'] = true;
        
        $block_status = $this->blockStatus($captcha);
        if($block_status !== false) {
            $return['message'] = $block_status;
            return $return;
        }

        $validatePassword = $this->validatePassword($newpass);
        if($validatePassword['error'] == 1){
            $return['message'] = $validatePassword['message'];
            return $return;
        }
        elseif($newpass !== $repeatnewpass){
            $return['message'] = self::$lang["newpassword_nomatch"];
            return $return;
        }

        $strength = $this->minPasswordStrength($newpass);
        if($strength !== false){
            $return['message'] = $strength['message'];
            return $return;
        }

        $user = $this->getBaseUser($uid);
        if(empty($user)){
            $this->addAttempt();
            $return['message'] = self::$lang["system_error"] . " #13";
            return $return;
        }

        if(!password_verify($currpass, $user['password'])){
            $this->addAttempt();
            $return['message'] = self::$lang["password_incorrect"];
            return $return;
        }

        self::$db->update($this->table_users, array('password' => $this->getHash($newpass)), array('id' => $uid));
        $return['error'] = false;
        $return['message'] = self::$lang["password_changed"];
        return $return;
    }
    
    /**
    * Changes a user's email
    * @param int $uid
    * @param string $email
    * @param string $password
    * @param string $captcha = NULL
    * @return array $return
    */
    public function changeEmail($uid, $email, $password, $captcha = NULL){
        $return = array();
        $return['error'] = true;
        
        $block_status = $this->blockStatus($captcha);
        if($block_status !== false) {
            $return['message'] = $block_status;
            return $return;
        }
        
        $validateInfo = $this->validateEmailPassword($email, $password);
        if($validateInfo !== false) {
            $return['message'] = $validateInfo;
            return $return;
        }

        if ($this->isEmailTaken($email)) {
            $this->addAttempt();
            $return['message'] = self::$lang["email_taken"];
            return $return;
        }

        $user = $this->getBaseUser($uid);
        if (empty($user)) {
            $this->addAttempt();
            $return['message'] = self::$lang["system_error"] . " #14";
            return $return;
        }

        if (!password_verify($password, $user['password'])) {
            $this->addAttempt();
            $return['message'] = self::$lang["password_incorrect"];
            return $return;
        }

        if ($email == $user['email']) {
            $this->addAttempt();
            $return['message'] = self::$lang["newemail_match"];
            return $return;
        }

        if(self::$db->update($this->table_users, array('email' => $email), array('id' => $uid)) === false){
            $return['message'] = self::$lang["system_error"] . " #15";
            return $return;
        }

        $return['error'] = false;
        $return['message'] = self::$lang["email_changed"];
        return $return;
    }
    
    /**
    * Informs if a user is locked out
    * @return string
    */
    public function isBlocked(){
        $ip = $this->getUserIP();
        $this->deleteAttempts($ip, false);
        $attempts = self::$db->count($this->table_attempts, array('ip' => $ip), false);
        if($attempts < intval($this->attempts_before_verify)){
            return "allow";
        }
        if($attempts < intval($this->attempts_before_ban)){
            return "verify";
        }
        return "block";
    }
    
    /**
     * Checks to see if the user is blocked or needs to verify 
     * @param string $captcha This should be the captcha string
     * @return string|false If the verification fails or the user is blocked will return an error message else will return false
     */
    protected function blockStatus($captcha){
        $block_status = $this->isBlocked();
        if ($block_status == "verify") {
            if ($this->checkCaptcha($captcha) === false) {
                return self::$lang["user_verify_failed"];
            }
        }

        if ($block_status == "block") {
            return self::$lang["user_blocked"];
        }
        return false;
    }
    
    /**
     * 
     * @param string $email
     * @param string $password
     * @return boolean
     */
    protected function validateEmailPassword($email, $password){
        $validateEmail = $this->validateEmail($email);
        if ($validateEmail['error'] == 1) {
            $this->addAttempt();
            return self::$lang["email_password_invalid"];
        }
        $validatePassword = $this->validatePassword($password);
        if ($validatePassword['error'] == 1) {
            $this->addAttempt();
            return self::$lang["email_password_invalid"];
        }
        return false;
    }
    
    /**
     * Verifies a captcha code
     * @param string $captcha
     * @return boolean
     */
    protected function checkCaptcha($captcha){
        try {
            $url = 'https://www.google.com/recaptcha/api/siteverify';
            $data = ['secret'   => 'your_secret_here',
            'response' => $captcha,
            'remoteip' => $this->getIp()];

            $options = [
                'http' => [
                'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
                'method'  => 'POST',
                'content' => http_build_query($data)
                ]
            ];

            $context  = stream_context_create($options);
            $result = file_get_contents($url, false, $context);
            return json_decode($result)->success;
        }
        catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Adds an attempt to database
     * @return boolean
     */
    protected function addAttempt(){
        return self::$db->insert($this->table_attempts, array('ip' => $this->getUserIP(), 'expirydate' => date("Y-m-d H:i:s", strtotime($this->attack_mitigation_time))));
    }
    
    /**
     * Deletes all attempts for a given IP from database
     * @param string $ip
     * @param boolean $all
     * @return boolean
     */
    protected function deleteAttempts($ip, $all = true){
        if($all === true){
            return self::$db->delete($this->table_attempts, array('ip' => $ip));
        }
        return self::$db->delete($this->table_attempts, array('ip' => $ip, 'expirydate' => array('<=', strtotime(date("Y-m-d H:i:s")))));
    }
    
    /**
    * Returns a random string of a specified length
    * @param int $length
    * @return string $key
    */
    public function getRandomKey($length = 20){
        $chars = "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6";
        $key = "";
        for($i = 0; $i < $length; $i++){
            $key .= $chars{mt_rand(0, strlen($chars) - 1)};
        }
        return $key;
    }
    
    /**
    * Returns IP address
    * @return string $ip
    */
    protected function getIp(){
        if(isset($_SERVER['HTTP_X_FORWARDED_FOR']) && $_SERVER['HTTP_X_FORWARDED_FOR'] != ''){
            return $_SERVER['HTTP_X_FORWARDED_FOR'];
        }
        else{
            return $_SERVER['REMOTE_ADDR'];
        }
    }
    
    /**
    * Returns is user logged in
    * @return boolean
    */
    public function isLogged(){
        return (isset($_COOKIE[$this->cookie_name]) && $this->checkSession($_COOKIE[$this->cookie_name]));
    }
    
    /**
     * Returns current session hash
     * @return string
     */
    public function getSessionHash(){
        return $_COOKIE[$this->cookie_name];
    }
    
    /**
     * Compare user's password with given password
     * @param int $userid
     * @param string $password_for_check
     * @return bool
     */
    public function comparePasswords($userid, $password_for_check){
        $data = self::$db->select($this->table_users, array('id' => $userid), array('password'));
        if(empty($data)){
            return false;
        }
        return password_verify($password_for_check, $data['password']);
    }
    
    /**
     * Returns the user information for the user who is currently logged in
     * @param int|boolean $userID
     * @return mixed If the user is logged in will return their information else will return false
     */
    public function getUserInfo($userID = false){
        if(is_array($this->userInfo) && !is_numeric($userID)){
            return $this->userInfo;
        }
        else{
            if(is_numeric($userID)){
                return $this->getUser($userID);
            }
            $userInfo = $this->getUser($this->getUserID());
            if(!empty($userInfo)){
                $this->userInfo = $userInfo;
                $this->userID = $userInfo['id'];
                return $this->userInfo;
            }
        }
        return false;
    }
    
    /**
     * Gets the users unique ID which has been assigned in the database
     * @return int This should be the users unique ID if logged in else will be 0
     */
    public function getUserID(){
        if(is_int($this->userID)){
            return $this->userID;
        }
        elseif($this->isLogged()){
            $this->userID = intval($this->getSessionUID($this->getSessionHash()));
            return $this->userID;
        }
        return 0;
    }
    
    /**
     * Returns the user IP Address
     * @return string This will be the users IP address
     */
    public function getUserIP(){
        return $this->getIp();
    }

    /**
     * Returns the users email address if the user is logged in
     * @return string This should be the users IP address if the user is logged in
     */
    public function getUserEmail(){
        if(!isset($this->userInfo)){$this->getUserInfo();}
        return $this->userInfo['email'];
    }
    
    /**
     * Returns the users first name from the users information if they are logged in
     * @return string This should be the users first name
     */
    public function getFirstname(){
        if(!isset($this->userInfo)){$this->getUserInfo();}
        return $this->userInfo['first_name'];
    }
    
    /**
     * Returns the users last name from the users information if they are logged in
     * @return string This should be the users last name
     */
    public function getLastname(){
        if(!isset($this->userInfo)){$this->getUserInfo();}
        return $this->userInfo['last_name'];
    }
    
    /**
     * Returns any stored settings from the database that the user may have
     * @param int|false $userID If you wish to get settings for a specific user set this here else to get settings for current user leave this blank or set to false
     * @return array 
     */
    public function getUserSettings($userID = false){
        $this->getUserInfo($userID);
        return unserialize($this->userInfo['settings']);
    }
    
    /**
     * Sets the stored settings in the database for the given user
     * @param array $vars This should be an array of any settings you wish to add the the user
     * @param int $userID This should be the user ID that you are applying the settings update to
     * @return boolean If the settings are updated successfully will return true else returns false
     */
    public function setUserSettings($vars, $userID = false){
        if(is_array($vars)){
            return self::$db->update($this->table_users, array('settings' => serialize(array_filter($vars))), array('id' => $userID), 1);
        }
        return false;
    }
}