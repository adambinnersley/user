<?php
/**
 * DBAL User class
 * @author Adam Binnersley
 * @version 1.0.0
 * @requires PHP 5.4.0 or greater
 */

namespace UserAuth;

use PHPMailer;
use DBAL\Database;
use ZxcvbnPhp\Zxcvbn as PasswordStrength;

class User implements UserInterface{
    protected static $db;
    protected static $lang;
    protected $config;
    
    protected $userID;
    protected $userInfo;
    
    protected $storageType = 'database';

    /**
     * Initiates essential objects
     * @param DriverManager $db
     * @param Config $config
     * @param string $language
     */
    public function __construct(Database $db, $config, $language = "en_GB"){
        self::$db = $db;
        $this->config = $config;
        
        require "languages/{$language}.php";
        self::$lang = $lang;

        date_default_timezone_set($this->config->site_timezone);
    }

    /**
     * Logs a user in
     * @param string $email
     * @param string $password
     * @param int $remember
     * @param string $captcha = NULL
     * @return array $return
     */
    public function login($email, $password, $remember = true, $captcha = NULL){
        $return['error'] = true;

        $block_status = $this->isBlocked();
        if($block_status == "verify"){
            if($this->checkCaptcha($captcha) == false){
                $return['message'] = self::$lang["user_verify_failed"];
                return $return;
            }
        }

        if($block_status == "block"){
            $return['message'] = self::$lang["user_blocked"];
            return $return;
        }

        $validateEmail = $this->validateEmail($email);
        $validatePassword = $this->validatePassword($password);
        if($validateEmail['error'] == 1){
            $this->addAttempt();
            $return['message'] = self::$lang["email_password_invalid"];
            return $return;
        }
        elseif($validatePassword['error'] == 1){
            $this->addAttempt();
            $return['message'] = self::$lang["email_password_invalid"];
            return $return;
        }
        elseif($remember != 0 && $remember != 1){
            $this->addAttempt();
            $return['message'] = self::$lang["remember_me_invalid"];
            return $return;
        }

        $user = $this->checkUsernamePassword($email, $password);
        if(!$user){
            $this->addAttempt();
            $return['message'] = self::$lang["email_password_incorrect"];
            return $return;
        }

        if($user['isactive'] != 1){
            $this->addAttempt();
            $return['message'] = self::$lang["account_inactive"];
            return $return;
        }
        
        $sessiondata = $this->addSession($user['uid'], $remember);
        if($sessiondata == false){
            $return['message'] = self::$lang["system_error"] . " #01";
            return $return;
        }

        $return['error'] = false;
        $return['message'] = self::$lang["logged_in"];
        $return['hash'] = $sessiondata['hash'];
        $return['expire'] = $sessiondata['expiretime'];
        $return['cookie_name'] = $this->config->cookie_name;
        return $return;
    }
    
    /**
     * Checks to see if the username and password match that whats in the database
     * @param string $username This should be the users email address
     * @param string $password This should be the users password
     * @return array|boolean If the information is correct the users information will be returned else will return false
     */
    protected function checkUsernamePassword($username, $password){
        return self::$db->select($this->config->table_users, array('email' => strtolower($username), 'password' => $this->getHash($password)));
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
    public function register($email, $password, $repeatpassword, $params = array(), $captcha = NULL, $sendmail = NULL){
        $return['error'] = true;
        $block_status = $this->isBlocked();

        if($block_status == "verify"){
            if($this->checkCaptcha($captcha) == false){
                $return['message'] = self::$lang["user_verify_failed"];
                return $return;
            }
        }

        if($block_status == "block"){
            $return['message'] = self::$lang["user_blocked"];
            return $return;
        }

        if($password !== $repeatpassword){
            $return['message'] = self::$lang["password_nomatch"];
            return $return;
        }

        // Validate email
        $validateEmail = $this->validateEmail($email);
        if($validateEmail['error'] == 1){
            $return['message'] = $validateEmail['message'];
            return $return;
        }

        // Validate password
        $validatePassword = $this->validatePassword($password);
        if($validatePassword['error'] == 1){
            $return['message'] = $validatePassword['message'];
            return $return;
        }

        $strength = new PasswordStrength();
        if($strength->passwordStrength($password)['score'] < intval($this->config->password_min_score)){
            $return['message'] = self::$lang['password_weak'];
            return $return;
        }

        if($this->isEmailTaken($email)){
            $this->addAttempt();
            $return['message'] = self::$lang["email_taken"];
            return $return;
        }

        $addUser = $this->addUser($email, $password, $params, $sendmail);
        if($addUser['error'] != 0){
            $return['message'] = $addUser['message'];
            return $return;
        }

        $return['error'] = false;
        $return['message'] = ($sendmail == true ? self::$lang["register_success"] : self::$lang['register_success_emailmessage_suppressed']);
        return $return;
    }
    
    /**
    * Activates a user's account
    * @param string $key
    * @return array $return
    */
    public function activate($key){
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
        
        self::$db->update($this->config->table_users, array('isactive' => 1), array('id' => $request['uid']));
        $this->deleteRequest($getRequest['id']);

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
        $return['error'] = true;

        if($this->isBlocked() == "block"){
            $return['message'] = self::$lang["user_blocked"];
            return $return;
        }

        $validateEmail = $this->validateEmail($email);
        if($validateEmail['error'] == 1){
            $return['message'] = self::$lang["email_invalid"];
            return $return;
        }

        $row = self::$db->query("SELECT `id` FROM `{$this->config->table_users}` WHERE `email` = ?;", array($email));
	if(!$row){
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
        $return['message'] = ($sendmail == true ? self::$lang["reset_requested"] : self::$lang['reset_requested_emailmessage_suppressed']);
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
        return password_hash($password, PASSWORD_DEFAULT, ['cost' => $this->config->bcrypt_cost]);
    }
    
    /**
    * Gets UID for a given email address and returns an array
    * @param string $email
    * @return array $uid
    */
    public function getUID($email){
        if(is_numeric($this->userID)){
            return $this->userID;
        }
        else{
            $row = self::$db->query("SELECT `id` FROM `{$this->config->table_users}` WHERE `email` = ?;", array($email));
            if(!$row){
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

        $data['hash'] = sha1($this->config->site_key . microtime());
        $this->deleteExistingSessions($uid);
        if($remember == true){
            $data['expire'] = date("Y-m-d H:i:s", strtotime($this->config->cookie_remember));
            $data['expiretime'] = strtotime($data['expire']);
        }
        else{
            $data['expire'] = date("Y-m-d H:i:s", strtotime($this->config->cookie_forget));
            $data['expiretime'] = 0;
        }

        if(!self::$db->insert($this->config->table_sessions, array('uid' => $uid, 'hash' => $data['hash'], 'expiredate' => $data['expire'], 'ip' => $this->getIp(), 'agent' => (isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : ''), 'cookie_crc' => sha1($data['hash'] . $this->config->site_key)))){
            return false;
        }

        $data['expire'] = strtotime($data['expire']);
        return $data;
    }
    
    /**
    * Removes all existing sessions for a given UID
    * @param int $uid
    * @return boolean
    */
    protected function deleteExistingSessions($uid){
        return self::$db->delete($this->config->table_sessions, array('uid' => $uid));
    }
    
    /**
    * Removes a session based on hash
    * @param string $hash
    * @return boolean
    */
    protected function deleteSession($hash){
        return self::$db->delete($this->config->table_sessions, array('hash' => $hash));
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

        $row = self::$db->query("SELECT `id`, `uid`, `expiredate`, `ip`, `agent`, `cookie_crc` FROM `{$this->config->table_sessions}` WHERE `hash` = ?;", array($hash));
        if(!$row){
            return false;
        }

        if(strtotime(date("Y-m-d H:i:s")) > strtotime($row['expiredate'])){
            $this->deleteExistingSessions($row['uid']);
            return false;
        }

        if($this->getIp() != $row['ip']){
            return false;
        }

        if($row['cookie_crc'] == sha1($hash . $this->config->site_key)){
            return true;
        }

        return false;
    }
    
    /**
    * Retrieves the UID associated with a given session hash
    * @param string $hash
    * @return int $uid
    */
    public function getSessionUID($hash){
        $row = self::$db->query("SELECT `uid` FROM `{$this->config->table_sessions}` WHERE `hash` = ?;", array($hash));
        if(!$row){
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
        self::$db->query("SELECT count(*) FROM `{$this->config->table_users}` WHERE `email` = ?;", array($email));
        if(self::$db->numRows() == 0){
            return false;
        }
        return true;
    }
    
    /**
    * Adds a new user to database
    * @param string $email      -- email
    * @param string $password   -- password
    * @param array $params      -- additional params
    * @return int $uid
    */
    protected function addUser($email, $password, $params = array(), &$sendmail){
        $return['error'] = true;

        $safeemail = htmlentities(strtolower($email));
        $requiredParams = array($safeemail, $this->getHash($password), ($sendmail ? 0 : 1));
        if(is_array($params)&& count($params) > 0){
            $setParams = array_merge($requiredParams, $params);
        }
        else{$setParams = $requiredParams;}

        if(!self::$db->insert($this->config->table_users, $setParams)){
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
        $data = self::$db->fetchAssoc("SELECT `email`, `password`, `isactive` FROM `{$this->config->table_users}` WHERE `id` = ?", array($uid));
        if(!$data){
            return false;
        }
        
        $data['uid'] = $uid;
        return $data;
    }
    
    /**
    * Gets public user data for a given UID and returns an array, password is not returned
    * @param int $uid
    * @return array $data
    */
    public function getUser($uid){
        $data = self::$db->fetchAssoc("SELECT * FROM `{$this->config->table_users}` WHERE `id` = ?;", array($uid));
        if(!$data){
            return false;
        }
        $data['uid'] = $uid;
        unset($data['password']);
        return $data;
    }
    
    /**
    * Allows a user to delete their account
    * @param int $uid
    * @param string $password
    * @param string $captcha = NULL
    * @return array $return
    */
    public function deleteUser($uid, $password, $captcha = NULL){
        $return['error'] = true;

        $block_status = $this->isBlocked();
        if($block_status == "verify"){
            if($this->checkCaptcha($captcha) == false){
                $return['message'] = self::$lang["user_verify_failed"];
                return $return;
            }
        }

        if($block_status == "block"){
            $return['message'] = self::$lang["user_blocked"];
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

        if(!self::$db->delete($this->config->table_users, array('id' => $uid)) || !self::$db->delete($this->config->table_sessions, array('uid' => $uid)) || !self::$db->delete($this->config->table_requests, array('uid' => $uid))){
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
    * @param boolean $sendmail = NULL
    * @return boolean
    */
    protected function addRequest($uid, $email, $type, &$sendmail){
        $return['error'] = true;

        if($type != "activation" && $type != "reset"){
            $return['message'] = self::$lang["system_error"] . " #08";
            return $return;
        }

        // if not set, set manually, check config data
        if($sendmail === NULL){
            $sendmail = true;
            if(($type == "reset" && $this->config->emailmessage_suppress_reset === true) || ($type == "activation" && $this->config->emailmessage_suppress_activation === true)){
                $sendmail = false;
                $return['error'] = false;
                return $return;
            }
        }

        $row = self::$db->fetchAssoc("SELECT `id`, `expire` FROM `{$this->config->table_requests}` WHERE `uid` = ? AND `type` = ?;", array($uid, $type));
        if($row){
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
        if(!self::$db->insert($this->config->table_requests, array('uid' => $uid, 'rkey' => $key, 'expire' => date("Y-m-d H:i:s", strtotime($this->config->request_key_expiration)), 'type' => $type))){
            $return['message'] = self::$lang["system_error"] . " #09";
            return $return;
        }

        if($sendmail === true){
            if($type == "activation"){
                $mailsent = $this->sendEmail(
                    $email,
                    sprintf(self::$lang['email_activation_subject'], $this->config->site_name),
                    sprintf(self::$lang['email_activation_body'], $this->config->site_url, $this->config->site_activation_page, $key),
                    sprintf(self::$lang['email_activation_altbody'], $this->config->site_url, $this->config->site_activation_page, $key)
                );
            }else{
                $mailsent = $this->sendEmail(
                    $email,
                    sprintf(self::$lang['email_reset_subject'], $this->config->site_name),
                    sprintf(self::$lang['email_reset_body'], $this->config->site_url, $this->config->site_password_reset_page, $key),
                    sprintf(self::$lang['email_reset_altbody'], $this->config->site_url, $this->config->site_password_reset_page, $key)
                );
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
        $return['error'] = true;
        
        $request = self::$db->fetchAssoc("SELECT `id`, `uid`, `expire` FROM `{$this->config->table_requests}` WHERE `rkey` = ? AND `type` = ? LIMIT 1;", array($key, $type));
        if(!$request){
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
        return self::$db->delete($this->config->table_requests, array('id' => $id));
    }
    
    /**
    * Verifies that a password is valid and respects security requirements
    * @param string $password
    * @return array $return
    */
    protected function validatePassword($password){
        $return['error'] = true;
        if(strlen($password) < (int)$this->config->verify_password_min_length){
            $return['message'] = self::$lang["password_short"];
            return $return;
        }

        $return['error'] = false;
        return $return;
    }
    
    /**
    * Verifies that an email is valid
    * @param string $email
    * @return array $return
    */
    protected function validateEmail($email){
        $return['error'] = true;

        if(strlen($email) < (int)$this->config->verify_email_min_length){
            $return['message'] = self::$lang["email_short"];
            return $return;
        }elseif(strlen($email) > (int)$this->config->verify_email_max_length){
            $return['message'] = self::$lang["email_long"];
            return $return;
        }elseif(!filter_var($email, FILTER_VALIDATE_EMAIL)){
            $return['message'] = self::$lang["email_invalid"];
            return $return;
        }

        if((int)$this->config->verify_email_use_banlist){
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
        $return['error'] = true;
        $block_status = $this->isBlocked();

        if($block_status == "verify"){
            if($this->checkCaptcha($captcha) == false){
                $return['message'] = self::$lang["user_verify_failed"];
                return $return;
            }
        }

        if($block_status == "block"){
            $return['message'] = self::$lang["user_blocked"];
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
            // Passwords don't match
            $return['message'] = self::$lang["newpassword_nomatch"];
            return $return;
        }

        $strength = new PasswordStrength();
        if($strength->passwordStrength($password)['score'] < intval($this->config->password_min_score)){
            $return['message'] = self::$lang['password_weak'];
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

        $query = self::$db->update($this->config->table_users, array('password' => $this->getHash($password)), array('id' => $data['uid']));
        if($query->rowCount() == 0){
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
    public function resendActivation($email, $sendmail = NULL){
        $return['error'] = true;

        if($this->isBlocked() == "block"){
            $return['message'] = self::$lang["user_blocked"];
            return $return;
        }

        if($sendmail == NULL){
            $return['message'] = self::$lang['function_disabled'];
            return $return;
        }

        $validateEmail = $this->validateEmail($email);
        if($validateEmail['error'] == 1){
            $return['message'] = $validateEmail['message'];
            return $return;
        }

        $row = self::$db->fetchAssoc("SELECT `id` FROM `{$this->config->table_users}` WHERE `email` = ?;", array($email));
        if(!$row){
            $this->addAttempt();
            $return['message'] = self::$lang["email_incorrect"];
            return $return;
        }

        if($this->getBaseUser($row['id'])['isactive'] == 1){
            $this->addAttempt();
            $return['message'] = self::$lang["already_activated"];
            return $return;
        }

        $addRequest = $this->addRequest($row['id'], $email, "activation", $sendmail);
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
        $return['error'] = true;
        
        $block_status = $this->isBlocked();
        if($block_status == "verify"){
            if($this->checkCaptcha($captcha) == false){
                $return['message'] = self::$lang["user_verify_failed"];
                return $return;
            }
        }

        if($block_status == "block"){
            $return['message'] = self::$lang["user_blocked"];
            return $return;
        }

        $validatePassword = $this->validatePassword($currpass);
        if($validatePassword['error'] == 1){
            $this->addAttempt();
            $return['message'] = $validatePassword['message'];
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

        $strength = new PasswordStrength();
        if($strength->passwordStrength($newpass)['score'] < intval($this->config->password_min_score)){
            $return['message'] = self::$lang['password_weak'];
            return $return;
        }

        $user = $this->getBaseUser($uid);
        if(!$user){
            $this->addAttempt();
            $return['message'] = self::$lang["system_error"] . " #13";
            return $return;
        }

        if(!password_verify($currpass, $user['password'])){
            $this->addAttempt();
            $return['message'] = self::$lang["password_incorrect"];
            return $return;
        }

        self::$db->update($this->config->table_users, array('password' => $this->getHash($newpass)), array('id' => $uid));
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
        $return['error'] = true;
        $block_status = $this->isBlocked();

        if ($block_status == "verify") {
            if ($this->checkCaptcha($captcha) == false) {
                $return['message'] = self::$lang["user_verify_failed"];

                return $return;
            }
        }

        if ($block_status == "block") {
            $return['message'] = self::$lang["user_blocked"];

            return $return;
        }

        $validateEmail = $this->validateEmail($email);

        if ($validateEmail['error'] == 1) {
            $return['message'] = $validateEmail['message'];

            return $return;
        }

        if ($this->isEmailTaken($email)) {
            $this->addAttempt();
            $return['message'] = self::$lang["email_taken"];

            return $return;
        }

        $validatePassword = $this->validatePassword($password);

        if ($validatePassword['error'] == 1) {
            $return['message'] = self::$lang["password_notvalid"];

            return $return;
        }

        $user = $this->getBaseUser($uid);

        if (!$user) {
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

        $query = self::$db->update($this->config->table_users, array('email' => $email), array('id' => $uid));
        if($query == 0){
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
        self::$db->query("SELECT count(*) FROM `{$this->config->table_attempts}` WHERE `ip` = ?;", array($ip));
        $attempts = self::$db->rowCount();
        if($attempts < intval($this->config->attempts_before_verify)){
            return "allow";
        }
        if($attempts < intval($this->config->attempts_before_ban)){
            return "verify";
        }
        return "block";
    }
    
    /**
     * Verifies a captcha code
     * @param string $captcha
     * @return boolean
     */
    protected function checkCaptcha($captcha){
        return true;
    }
    
    /**
     * Adds an attempt to database
     * @return boolean
     */
    protected function addAttempt(){
        return self::$db->insert($this->config->table_attempts, array('ip' => $this->getUserIP(), 'expirydate' => date("Y-m-d H:i:s", strtotime($this->config->attack_mitigation_time))));
    }
    
    /**
     * Deletes all attempts for a given IP from database
     * @param type $ip
     * @param type $all
     * @return boolean
     */
    protected function deleteAttempts($ip, $all = true){
        if($all == true){
            return self::$db->delete($this->config->table_attempts, array('ip' => $ip));
        }
        return self::$db->query("DELETE FROM `{$this->config->table_attempts}` WHERE `ip` = ? AND `expirydate` <= ?;", array($ip, strtotime(date("Y-m-d H:i:s"))));
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
        return (isset($_COOKIE[$this->config->cookie_name]) && $this->checkSession($_COOKIE[$this->config->cookie_name]));
    }
    
    /**
     * Returns current session hash
     * @return string
     */
    public function getSessionHash(){
        return $_COOKIE[$this->config->cookie_name];
    }
    
    /**
     * Compare user's password with given password
     * @param int $userid
     * @param string $password_for_check
     * @return bool
     */
    public function comparePasswords($userid, $password_for_check){
        $data = self::$db->select("SELECT `password` FROM `{$this->config->table_users}` WHERE `id` = ?;", array($userid));
        if(!$data){
            return false;
        }
        return password_verify($password_for_check, $data['password']);
    }
    
    public function getUserInfo($userID = false){
        if(is_array($this->userInfo)){
            return $this->userInfo;
        }
        else{
            if(!is_numeric($userID)){$this->getUserID();}
            $this->userInfo = self::$db->select($this->config->table_users, array('id' => $userID));
            $this->userID = $this->userInfo['id'];
            return $this->userInfo;
        }
    }
    
    /**
     * Send the emails based on the given parameters
     * @param string $email
     * @param string $subject
     * @param string $body
     * @param string $altbody
     * @return boolean
     */
    protected function sendEmail($email, $subject, $body, $altbody){
        // Check configuration for SMTP parameters
        $mail = new PHPMailer;
        $mail->CharSet = $this->config->mail_charset;
        if($this->config->smtp){
            $mail->isSMTP();
            $mail->Host = $this->config->smtp_host;
            $mail->SMTPAuth = $this->config->smtp_auth;
            if(!is_null($this->config->smtp_auth)){
                $mail->Username = $this->config->smtp_username;
                $mail->Password = $this->config->smtp_password;
            }
            $mail->Port = $this->config->smtp_port;
            if(!is_null($this->config->smtp_security)){
                $mail->SMTPSecure = $this->config->smtp_security;
            }
        }

        $mail->From = $this->config->site_email;
        $mail->FromName = $this->config->site_name;
        $mail->addAddress($email);
        $mail->isHTML(true);
        $mail->Subject = $subject;
        $mail->Body = $body;
        $mail->AltBody = $altbody;
        return $mail->send();
    }
    
    /**
     * Gets the users unique ID which has been assigned in the database
     * @return int This should be the users unique ID
     */
    public function getUserID(){
        if(!isset($this->userID)){$this->getUserInfo();}
        return $this->userID;
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
     * @param int|boolean $userID If you wish to get settings for a specific user set this here else to get settings for current user leave this blank or set to false
     * @return array 
     */
    public function getUserSettings($userID = false){
        $this->getUserInfo($userID);
        return unserialize($this->userInfo['settings']);
    }
    
    public function setUserSettings($vars, $userID = false){
        if(is_array($vars)){
            return self::$db->update($this->config->table_users, array('settings' => serialize(array_filter($vars))), array('id' => $userID), 1);
        }
        return false;
    }
}