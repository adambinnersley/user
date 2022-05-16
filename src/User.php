<?php
/**
 * DBAL User class
 * @author Adam Binnersley
 * @requires PHP 7.0 or greater
 */
namespace UserAuth;

use DBAL\Database;
use ZxcvbnPhp\Zxcvbn as PasswordStrength;

class User implements UserInterface
{
    protected $db;
    public $lang;
    
    protected $userID;
    protected $userInfo;
    
    protected $key;
    
    protected $table_users = 'users';
    protected $table_sessions = 'sessions';
    protected $table_requests = 'requests';
    protected $table_attempts = 'attempts';
    
    protected $activation_page = 'activate';
    protected $reset_page = 'reset';
    
    protected $attack_mitigation_time = '+30 minutes';
    protected $attempts_before_ban = 30;
    protected $attempts_before_verify = 5;
    protected $use_banlist = true;
    
    public $site_timezone = 'Europe/London';
    
    public $cookie_name = 'authID';
    public $cookie_forget = '+30 minutes';
    public $cookie_remember = '+1 year';
    
    protected $password_cost = 11;
    protected $password_min_score = 3;
    
    protected $request_key_expiration = '+2 days';
    
    public $send_activation_email = true;
    public $send_reset_email = true;
    
    public $emailFrom = 'user@example.com';
    public $emailFromName = 'User Account';

    /**
     * Initiates essential objects
     * @param Database $db
     * @param string $language
     */
    public function __construct(Database $db, $language = "en_GB")
    {
        $this->db = $db;
        $this->setLanguageFile(dirname(__FILE__)."/languages/{$language}.php");
        date_default_timezone_set($this->site_timezone);
    }
    
    /**
     * Getter Will retrieve set variables
     * @param string $name This should be the string value name
     * @return mixed This will be the string value if it exists
     */
    public function __get($name)
    {
        if (property_exists($this, $name)) {
            return $this->$name;
        }
        return false;
    }
    
    /**
     * Setter Will set class variables
     * @param string $name This should be the variable name
     * @param mixed $value This should be the variable value you wish to set it to
     */
    public function __set($name, $value)
    {
        if (property_exists($this, $name)) {
            $this->$name = $value;
        }
    }
    
    /**
     * Sets the language file
     * @property array $lang This variable is retrieved from the language file
     * @param string $location This should be the location of the language file you wish to use
     * @return $this
     */
    public function setLanguageFile($location)
    {
        if (file_exists($location)) {
            $lang = [];
            require $location;
            $this->lang = $lang;
        }
        return $this;
    }
    
    /**
     * Returns the language array
     * @return array The current language array will be returned
     */
    public function getLanguageArray()
    {
        return $this->lang;
    }
    
    /**
     * Sets the language from an array
     * @param array $language This should be and array containing the array
     * @return $this
     */
    public function setLanguageArray($language)
    {
        if (is_array($language)) {
            $this->lang = $language;
        }
        return $this;
    }

    /**
     * Logs a user in
     * @param string $email
     * @param string $password
     * @param boolean $remember
     * @param string $captcha = NULL
     * @return array $return
     */
    public function login($email, $password, $remember = true, $captcha = null)
    {
        $return = [];
        $return['error'] = true;
        
        $block_status = $this->blockStatus($captcha);
        if ($block_status !== false) {
            $return['message'] = $block_status;
            return $return;
        }

        $validateInfo = $this->validateEmailPassword($email, $password);
        if ($validateInfo !== false) {
            $return['message'] = $validateInfo;
            return $return;
        }

        $user = $this->checkUsernamePassword($email, $password);
        if (empty($user)) {
            $this->addAttempt();
            $return['message'] = $this->lang["email_password_incorrect"];
            return $return;
        }

        if ($user['isactive'] == 0) {
            $this->addAttempt();
            $return['message'] = $this->lang["account_inactive"];
            return $return;
        }
        
        $sessiondata = $this->addSession($user['id'], $remember);
        if ($sessiondata === false) {
            $return['message'] = $this->lang["system_error"] . " #01";
            return $return;
        }

        $this->userID = intval($user['id']);
        $return['error'] = false;
        $return['message'] = $this->lang["logged_in"];
        $return['hash'] = $sessiondata['hash'];
        $return['expire'] = $sessiondata['expiretime'];
        $return['cookie_name'] = $this->cookie_name;
        $return['user_id'] = $this->userID;
        return $return;
    }
    
    /**
     * Checks to see if the username and password match that whats in the database
     * @param string $username This should be the users email address
     * @param string $password This should be the users password
     * @return array|false If the information is correct the users information will be returned else will return false
     */
    public function checkUsernamePassword($username, $password)
    {
        $data = $this->db->select($this->table_users, ['email' => strtolower($username)], '*', [], false);
        if (empty($data)) {
            return false;
        }
        if (password_verify($password, $data['password']) === true) {
            unset($data['password']);
            return $data;
        }
        return false;
    }
    
    /**
     * Check to see if a user with the given email address exists
     * @param string $email This should be the email address that you wish to check
     * @return array|false If the users exists the information will be returned else will return false
     */
    public function checkEmailExists($email)
    {
        if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return $this->db->select($this->table_users, ['email' => $email], ['id'], [], false);
        }
        return false;
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
    public function register($email, $password, $repeatpassword, $params = [], $captcha = null, $sendmail = null)
    {
        $return = [];
        $return['error'] = true;
        
        $block_status = $this->blockStatus($captcha);
        if ($block_status !== false) {
            $return['message'] = $block_status;
            return $return;
        }

        if ($password !== $repeatpassword) {
            $return['message'] = $this->lang["password_nomatch"];
            return $return;
        }

        $strength = $this->minPasswordStrength($password);
        if ($strength !== false) {
            $return['message'] = $strength['message'];
            return $return;
        }
        
        if (!is_null($email)) {
            $validateInfo = $this->validateEmailPassword($email, $password);
            if ($validateInfo !== false) {
                $return['message'] = $validateInfo;
                return $return;
            }

            if ($this->isEmailTaken($email)) {
                $this->addAttempt();
                $return['message'] = $this->lang["email_taken"];
                return $return;
            }
        }

        $addUser = $this->addUser($email, $password, $params, $sendmail);
        if ($addUser['error'] != 0) {
            $return['message'] = $addUser['message'];
            return $return;
        }

        $return['error'] = false;
        $return['message'] = ($sendmail === true ? $this->lang["register_success"] : $this->lang['register_success_emailmessage_suppressed']);
        return $return;
    }
    
    /**
    * Activates a user's account
    * @param string $key
    * @return array $return
    */
    public function activate($key)
    {
        $return = [];
        $return['error'] = true;
        if ($this->isBlocked() == "block") {
            $return['message'] = $this->lang["user_blocked"];
            return $return;
        }
        if (strlen($key) !== 20) {
            $this->addAttempt();
            $return['message'] = $this->lang["activationkey_invalid"];
            return $return;
        }

        $request = $this->getRequest($key, "activation");
        if ($request['error'] == 1) {
            $return['message'] = $request['message'];
            return $return;
        }

        if ($this->getBaseUser($request['uid'])['isactive'] >= 1) {
            $this->addAttempt();
            $this->deleteRequest($request['id']);
            $return['message'] = $this->lang["system_error"] . " #02";
            return $return;
        }
        
        $this->db->update($this->table_users, ['isactive' => 1], ['id' => $request['uid']]);
        $this->deleteRequest($request['id']);

        $return['error'] = false;
        $return['message'] = $this->lang["account_activated"];

        return $return;
    }
    
    /**
    * Creates a reset key for an email address and sends email
    * @param string $email
    * @return array $return
    */
    public function requestReset($email, $sendmail = null)
    {
        $return = [];
        $return['error'] = true;

        if ($this->isBlocked() == "block") {
            $return['message'] = $this->lang["user_blocked"];
            return $return;
        }

        $validateEmail = $this->validateEmail($email);
        if ($validateEmail['error'] == 1) {
            $return['message'] = $validateEmail['message'];
            return $return;
        }

        $row = $this->checkEmailExists($email);
        if (empty($row)) {
            $this->addAttempt();
            $return['message'] = $this->lang["email_incorrect"];
            return $return;
        }

        $addRequest = $this->addRequest($row['id'], $email, "reset", $sendmail);
        if ($addRequest['error'] == 1) {
            $this->addAttempt();
            $return['message'] = $addRequest['message'];
            return $return;
        }

        $return['error'] = false;
        $return['message'] = ($sendmail === true ? $this->lang["reset_requested"] : $this->lang['reset_requested_emailmessage_suppressed']);
        return $return;
    }
    
    /**
    * Logs out the session, identified by hash
    * @param string $hash
    * @return boolean
    */
    public function logout($hash)
    {
        if (strlen($hash) != 40) {
            return false;
        }
        return $this->deleteSession($hash);
    }
    
    /**
    * Hashes provided password with Bcrypt
    * @param string $password
    * @return string
    */
    public function getHash($password)
    {
        return password_hash($password, PASSWORD_DEFAULT, ['cost' => $this->password_cost]);
    }
    
    /**
    * Gets UID for a given email address and returns an array
    * @param string $email
    * @return int|false
    */
    public function getUID($email)
    {
        if (is_int($this->userID)) {
            return $this->userID;
        }
        $row = $this->checkEmailExists($email);
        if (empty($row)) {
            return false;
        }
        return $row['id'];
    }

    /**
    * Creates a session for a specified user id
    * @param int $uid
    * @param boolean $remember
    * @return array $data
    */
    protected function addSession($uid, $remember)
    {
        $data = $this->getBaseUser($uid);
        if ($data === false) {
            return false;
        }
        $data['hash'] = sha1(SITE_KEY . microtime());
        if ($remember === true) {
            $data['expire'] = date("Y-m-d H:i:s", strtotime($this->cookie_remember));
            $data['expiretime'] = strtotime($data['expire']);
        } else {
            $data['expire'] = date("Y-m-d H:i:s", strtotime($this->cookie_forget));
            $data['expiretime'] = 0;
        }

        if (!$this->db->insert($this->table_sessions, ['uid' => $uid, 'hash' => $data['hash'], 'expiredate' => $data['expire'], 'ip' => $this->getIp(), 'agent' => (isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : ''), 'cookie_crc' => sha1($data['hash'] . SITE_KEY)])) {
            return false;
        }
        setcookie($this->cookie_name, $data['hash'], strtotime($data['expire']), '/', '', (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != 'off' ? true : false), true);
        $this->setLastLogin($uid, date('Y-m-d', strtotime($data['last_login'])));
        
        return $data;
    }
    
    /**
    * Removes all existing sessions for a given UID
    * @param int $uid
    * @return boolean
    */
    protected function deleteExistingSessions($uid)
    {
        return $this->db->delete($this->table_sessions, ['uid' => $uid]);
    }
    
    /**
    * Removes a session based on hash
    * @param string $hash
    * @return boolean
    */
    protected function deleteSession($hash)
    {
        return $this->db->delete($this->table_sessions, ['hash' => $hash]);
    }

    /**
    * Function to check if a session is valid
    * @param string $hash
    * @return boolean
    */
    public function checkSession($hash)
    {
        if (strlen($hash) != 40) {
            return false;
        }

        $row = $this->db->select($this->table_sessions, ['hash' => $hash], '*', [], false);
        if (empty($row)) {
            return false;
        }

        if (strtotime(date("Y-m-d H:i:s")) > strtotime($row['expiredate'])) {
            $this->deleteExistingSessions($row['uid']);
            return false;
        }

        if ($row['cookie_crc'] == sha1($hash . SITE_KEY)) {
            $this->userID = intval($row['uid']);
            $this->setLastLogin($row['uid']);
            return true;
        }

        return false;
    }
    
    /**
    * Retrieves the UID associated with a given session hash
    * @param string $hash
    * @return int|false
    */
    public function getSessionUID($hash)
    {
        return $this->db->fetchColumn($this->table_sessions, ['hash' => $hash], ['uid'], 0, [], false);
    }
    
     /**
    * Checks if an email is already in use
    * @param string $email
    * @return boolean
    */
    public function isEmailTaken($email)
    {
        if ($this->db->count($this->table_users, ['email' => $email], false) == 0) {
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
    protected function addUser($email, $password, $params = [], $sendmail = null)
    {
        $return = [];
        $return['error'] = true;

        $safeemail = (is_null($email) ? null : htmlentities(strtolower($email)));
        $requiredParams = ['email' => $safeemail, 'password' => $this->getHash($password), 'isactive' => ($sendmail ? 0 : 1)];
        if (is_array($params)&& count($params) > 0) {
            $setParams = array_merge($requiredParams, $params);
        } else {
            $setParams = $requiredParams;
        }

        if (!$this->db->insert($this->table_users, $setParams)) {
            $return['message'] = $this->lang["system_error"] . " #03";
            return $return;
        } elseif ($sendmail) {
            $this->addRequest($this->db->lastInsertId(), $email, "activation", $sendmail);
        }

        $return['error'] = false;
        return $return;
    }
    
    /**
    * Gets basic user data for a given UID and returns an array
    * @param int $uid
    * @return array $data
    */
    protected function getBaseUser($uid)
    {
        $data = $this->db->select($this->table_users, ['id' => $uid], ['email', 'password', 'isactive', 'last_login'], [], false);
        if (empty($data)) {
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
    public function getUser($uid)
    {
        if (is_integer($uid)) {
            $data = $this->db->select($this->table_users, ['id' => $uid], '*', [], false);
            if (empty($data)) {
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
    public function deleteUser($uid, $password, $captcha = null)
    {
        $return = [];
        $return['error'] = true;

        $block_status = $this->blockStatus($captcha);
        if ($block_status !== false) {
            $return['message'] = $block_status;
            return $return;
        }

        $validatePassword = $this->validatePassword($password);
        if ($validatePassword['error'] == 1) {
            $this->addAttempt();
            $return['message'] = $validatePassword['message'];
            return $return;
        }

        $user = $this->getBaseUser($uid);
        if(!$user){
            $return['message'] = $this->lang["account_inactive"];
            return $return;
        }
        
        if (!password_verify($password, $user['password'])) {
            $this->addAttempt();
            $return['message'] = $this->lang["password_incorrect"];
            return $return;
        }

        if (!$this->db->delete($this->table_users, ['id' => $uid])) {
            $return['message'] = $this->lang["system_error"] . " #04";
            return $return;
        }
        $this->db->delete($this->table_sessions, ['uid' => $uid]);
        $this->db->delete($this->table_requests, ['uid' => $uid]);

        $return['error'] = false;
        $return['message'] = $this->lang["account_deleted"];

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
    protected function addRequest($uid, $email, $type, $sendmail)
    {
        $return = [];
        $return['error'] = true;

        if ($sendmail === null) {
            $sendmail = true;
            if (($type == "reset" && $this->send_reset_email !== true) || ($type == "activation" && $this->send_activation_email !== true)) {
                $return['error'] = false;
                return $return;
            }
        }

        $row = $this->db->select($this->table_requests, ['uid' => $uid, 'type' => $type], ['id', 'expire'], [], false);
        if (!empty($row)) {
            if (strtotime(date("Y-m-d H:i:s")) < strtotime($row['expire'])) {
                $return['message'] = $this->lang["reset_exists"];
                return $return;
            }
            $this->deleteRequest($row['id']);
        }

        if ($type == "activation" && $this->getBaseUser($uid)['isactive'] >= 1) {
            $return['message'] = $this->lang["already_activated"];
            return $return;
        }
        
        $this->key = $this->getRandomKey(20);
        if (!$this->db->insert($this->table_requests, ['uid' => $uid, 'rkey' => $this->key, 'expire' => date("Y-m-d H:i:s", strtotime($this->request_key_expiration)), 'type' => $type])) {
            $return['message'] = $this->lang["system_error"] . " #05";
            return $return;
        }

        if ($sendmail === true) {
            $string = $type.'_page';
            $mailsent = sendEmail($email, sprintf($this->lang['email_'.$type.'_subject'], SITE_NAME), sprintf($this->lang['email_'.$type.'_altbody'], SITE_URL, $this->{$string}, $this->key), sprintf($this->lang['email_'.$type.'_body'], SITE_URL, $this->{$string}, $this->key), $this->emailFrom, $this->emailFromName);
            if (!$mailsent) {
                $this->deleteRequest($this->db->lastInsertId());
                $return['message'] = $this->lang["system_error"] . " #06";
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
    * @return array
    */
    public function getRequest($key, $type)
    {
        $return = [];
        $return['error'] = true;
        
        $request = $this->db->select($this->table_requests, ['rkey' => $key, 'type' => $type], ['id', 'uid', 'expire'], [], false);
        if (empty($request)) {
            $this->addAttempt();
            $return['message'] = $this->lang[$type."key_incorrect"];
            return $return;
        }
        
        if (strtotime(date("Y-m-d H:i:s")) > strtotime($request['expire'])) {
            $this->addAttempt();
            $this->deleteRequest($request['id']);
            $return['message'] = $this->lang[$type."key_expired"];
            return $return;
        }
        
        $return['error'] = false;
        return array_merge($return, $request);
    }
    
    /**
    * Deletes request from database
    * @param int $id
    * @return boolean
    */
    protected function deleteRequest($id)
    {
        return $this->db->delete($this->table_requests, ['id' => $id]);
    }
    
    /**
    * Verifies that a password is valid and respects security requirements
    * @param string $password
    * @return array $return
    */
    protected function validatePassword($password)
    {
        $return = [];
        $return['error'] = true;
        if (strlen($password) < 5) {
            $return['message'] = $this->lang["password_short"];
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
    protected function minPasswordStrength($password)
    {
        $return = [];
        $strength = new PasswordStrength();
        if ($strength->passwordStrength($password)['score'] < intval($this->password_min_score)) {
            $return['message'] = $this->lang['password_weak'];
            return $return;
        }
        return false;
    }
    
    /**
    * Verifies that an email is valid
    * @param string $email
    * @return array $return
    */
    protected function validateEmail($email)
    {
        $return = [];
        $return['error'] = true;

        if (strlen($email) < 5) {
            $return['message'] = $this->lang["email_short"];
            return $return;
        } elseif (strlen($email) > 100) {
            $return['message'] = $this->lang["email_long"];
            return $return;
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $return['message'] = $this->lang["email_invalid"];
            return $return;
        }

        if ($this->use_banlist === true) {
            $bannedEmails = json_decode(file_get_contents(__DIR__ . "/files/domains.json"));

            if (in_array(strtolower(explode('@', $email)[1]), $bannedEmails)) {
                $return['message'] = $this->lang["email_banned"];
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
    public function resetPass($key, $password, $repeatpassword, $captcha = null)
    {
        $return = [];
        $return['error'] = true;
        
        $block_status = $this->blockStatus($captcha);
        if ($block_status !== false) {
            $return['message'] = $block_status;
            return $return;
        }

        if (strlen($key) != 20) {
            $return['message'] = $this->lang["resetkey_invalid"];
            return $return;
        }

        $validatePassword = $this->validatePassword($password);
        if ($validatePassword['error'] == 1) {
            $return['message'] = $validatePassword['message'];
            return $return;
        }

        if ($password !== $repeatpassword) {
            $return['message'] = $this->lang["newpassword_nomatch"];
            return $return;
        }

        $strength = $this->minPasswordStrength($password);
        if ($strength !== false) {
            $return['message'] = $strength['message'];
            return $return;
        }
        
        $data = $this->getRequest($key, "reset");
        if ($data['error'] == 1) {
            $return['message'] = $data['message'];
            return $return;
        }

        $user = $this->getBaseUser($data['uid']);
        if (!$user) {
            $this->addAttempt();
            $this->deleteRequest($data['id']);
            $return['message'] = $this->lang["system_error"] . " #07";

            return $return;
        }

        if (password_verify($password, $user['password'])) {
            $this->addAttempt();
            $return['message'] = $this->lang["newpassword_match"];
            return $return;
        }

        if ($this->db->update($this->table_users, ['password' => $this->getHash($password)], ['id' => $data['uid']]) === false) {
            $return['message'] = $this->lang["system_error"] . " #08";
            return $return;
        }

        $this->deleteRequest($data['id']);
        $return['error'] = false;
        $return['message'] = $this->lang["password_reset"];
        return $return;
    }
    
    /**
    * Recreates activation email for a given email and sends
    * @param string $email
    * @return array $return
    */
    public function resendActivation($email)
    {
        $return = [];
        $return['error'] = true;

        if ($this->isBlocked() == "block") {
            $return['message'] = $this->lang["user_blocked"];
            return $return;
        }

        $validateEmail = $this->validateEmail($email);
        if ($validateEmail['error'] == 1) {
            $return['message'] = $validateEmail['message'];
            return $return;
        }

        $row = $this->checkEmailExists($email);
        if (empty($row)) {
            $this->addAttempt();
            $return['message'] = $this->lang["email_incorrect"];
            return $return;
        }

        if ($this->getBaseUser($row['id'])['isactive'] >= 1) {
            $this->addAttempt();
            $return['message'] = $this->lang["already_activated"];
            return $return;
        }

        $addRequest = $this->addRequest($row['id'], $email, "activation", null);
        if ($addRequest['error'] == 1) {
            $this->addAttempt();
            $return['message'] = $addRequest['message'];
            return $return;
        }

        $return['error'] = false;
        $return['message'] = $this->lang["activation_sent"];
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
    public function changePassword($uid, $currpass, $newpass, $repeatnewpass, $captcha = null)
    {
        $return = [];
        $return['error'] = true;
        
        $block_status = $this->blockStatus($captcha);
        if ($block_status !== false) {
            $return['message'] = $block_status;
            return $return;
        }

        $validatePassword = $this->validatePassword($newpass);
        if ($validatePassword['error'] == 1) {
            $return['message'] = $validatePassword['message'];
            return $return;
        } elseif ($newpass !== $repeatnewpass) {
            $return['message'] = $this->lang["newpassword_nomatch"];
            return $return;
        }

        $strength = $this->minPasswordStrength($newpass);
        if ($strength !== false) {
            $return['message'] = $strength['message'];
            return $return;
        }

        $user = $this->getBaseUser($uid);
        if (empty($user)) {
            $this->addAttempt();
            $return['message'] = $this->lang["system_error"] . " #09";
            return $return;
        }

        if (!password_verify($currpass, $user['password'])) {
            $this->addAttempt();
            $return['message'] = $this->lang["password_incorrect"];
            return $return;
        }

        $this->db->update($this->table_users, ['password' => $this->getHash($newpass)], ['id' => $uid]);
        $this->deleteExistingSessions($uid);
        $this->addSession($uid, true);
        $return['error'] = false;
        $return['message'] = $this->lang["password_changed"];
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
    public function changeEmail($uid, $email, $password, $captcha = null)
    {
        $return = [];
        $return['error'] = true;
        
        $block_status = $this->blockStatus($captcha);
        if ($block_status !== false) {
            $return['message'] = $block_status;
            return $return;
        }
        
        $validateInfo = $this->validateEmailPassword($email, $password);
        if ($validateInfo !== false) {
            $return['message'] = $validateInfo;
            return $return;
        }

        if ($this->isEmailTaken($email)) {
            $this->addAttempt();
            $return['message'] = $this->lang["email_taken"];
            return $return;
        }

        $user = $this->getBaseUser($uid);
        if (empty($user)) {
            $this->addAttempt();
            $return['message'] = $this->lang["system_error"] . " #10";
            return $return;
        }

        if (!password_verify($password, $user['password'])) {
            $this->addAttempt();
            $return['message'] = $this->lang["password_incorrect"];
            return $return;
        }

        if ($email == $user['email']) {
            $this->addAttempt();
            $return['message'] = $this->lang["newemail_match"];
            return $return;
        }

        if ($this->db->update($this->table_users, ['email' => $email], ['id' => $uid]) === false) {
            $return['message'] = $this->lang["system_error"] . " #11";
            return $return;
        }

        $return['error'] = false;
        $return['message'] = $this->lang["email_changed"];
        return $return;
    }
    
    /**
    * Informs if a user is locked out
    * @return string
    */
    public function isBlocked()
    {
        $ip = $this->getUserIP();
        $this->deleteAttempts($ip, false);
        $attempts = $this->db->count($this->table_attempts, ['ip' => $ip], false);
        if ($attempts < intval($this->attempts_before_verify)) {
            return "allow";
        }
        if ($attempts < intval($this->attempts_before_ban)) {
            return "verify";
        }
        return "block";
    }
    
    /**
     * Checks to see if the user is blocked or needs to verify
     * @param string $captcha This should be the captcha string
     * @return string|false If the verification fails or the user is blocked will return an error message else will return false
     */
    protected function blockStatus($captcha)
    {
        $block_status = $this->isBlocked();
        if ($block_status == "verify" && $captcha !== null) {
            if ($this->checkCaptcha($captcha) == false) {
                return $this->lang["user_verify_failed"];
            }
        }

        if ($block_status == "block") {
            return $this->lang["user_blocked"];
        }
        return false;
    }
    
    /**
     *
     * @param string $email
     * @param string $password
     * @return boolean
     */
    protected function validateEmailPassword($email, $password)
    {
        $validateEmail = $this->validateEmail($email);
        if ($validateEmail['error'] == 1) {
            $this->addAttempt();
            return $this->lang["email_password_invalid"];
        }
        $validatePassword = $this->validatePassword($password);
        if ($validatePassword['error'] == 1) {
            $this->addAttempt();
            return $this->lang["email_password_invalid"];
        }
        return false;
    }
    
    /**
     * Verifies a captcha code
     * @param string $captcha
     * @return boolean
     */
    protected function checkCaptcha($captcha)
    {
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
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Adds an attempt to database
     * @return boolean
     */
    protected function addAttempt()
    {
        return $this->db->insert($this->table_attempts, ['ip' => $this->getUserIP(), 'expirydate' => date("Y-m-d H:i:s", strtotime($this->attack_mitigation_time))]);
    }
    
    /**
     * Deletes all attempts for a given IP from database
     * @param string $ip
     * @param boolean $all
     * @return boolean
     */
    protected function deleteAttempts($ip, $all = true)
    {
        if ($all === true) {
            return $this->db->delete($this->table_attempts, ['ip' => $ip]);
        }
        return $this->db->delete($this->table_attempts, ['ip' => $ip, 'expirydate' => ['<=', date("Y-m-d H:i:s")]]);
    }
    
    /**
    * Returns a random string of a specified length
    * @param int $length
    * @return string $key
    */
    public function getRandomKey($length = 20)
    {
        $chars = "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6";
        $key = "";
        for ($i = 0; $i < $length; $i++) {
            $key .= $chars[mt_rand(0, strlen($chars) - 1)];
        }
        return $key;
    }
    
    /**
    * Returns IP address
    * @return string $ip
    */
    public function getIp()
    {
        if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && $_SERVER['HTTP_X_FORWARDED_FOR'] != '') {
            return $_SERVER['HTTP_X_FORWARDED_FOR'];
        }
        return $_SERVER['REMOTE_ADDR'];
    }
    
    /**
    * Returns is user logged in
    * @return boolean
    */
    public function isLogged()
    {
        if (isset($_COOKIE[$this->cookie_name])) {
            return $this->checkSession($_COOKIE[$this->cookie_name]);
        }
        return false;
    }
    
    /**
     * Returns current session hash
     * @return string
     */
    public function getSessionHash()
    {
        return $_COOKIE[$this->cookie_name];
    }
    
    /**
     * Compare user's password with given password
     * @param int $userid
     * @param string $password_for_check
     * @return bool
     */
    public function comparePasswords($userid, $password_for_check)
    {
        $data = $this->db->select($this->table_users, ['id' => $userid], ['password'], [], false);
        if (empty($data)) {
            return false;
        }
        return password_verify($password_for_check, $data['password']);
    }
    
    /**
     * Set the time that the user last logged in to the website
     * @param int $userid This should be the users ID
     * @param string|false If you want to set the date to a specific value enter the string here else set to false for current date/time
     * @return boolean If the field has been updated will return true else returns false
     */
    public function setLastLogin($userid, $date = false)
    {
        if ($date === false) {
            $userInfo = $this->getBaseUser($userid);
            if(is_array($userInfo)) {
                $date = date('Y-m-d', strtotime($userInfo['last_login']));
            }
        }
        if (is_numeric($userid) && $date !== date('Y-m-d')) {
            return $this->db->update($this->table_users, ['last_login' => date('Y-m-d H:i:s')], ['id' => intval($userid)]);
        }
        return false;
    }

    /**
     * Returns the user information for the user who is currently logged in
     * @param int|boolean $userID
     * @return mixed If the user is logged in will return their information else will return false
     */
    public function getUserInfo($userID = false)
    {
        if (is_array($this->userInfo) && !is_numeric($userID)) {
            return $this->userInfo;
        }
        if (is_numeric($userID)) {
            return $this->getUser(intval($userID));
        }
        $userInfo = $this->getUser(intval($this->getUserID()));
        if (!empty($userInfo)) {
            $this->userInfo = $userInfo;
            $this->userID = intval($userInfo['id']);
            return $this->userInfo;
        }
        return false;
    }
    
    /**
     * Gets the users unique ID which has been assigned in the database
     * @return int This should be the users unique ID if logged in else will be 0
     */
    public function getUserID()
    {
        if (is_int($this->userID) && $this->userID > 0) {
            return $this->userID;
        } elseif ($this->isLogged()) {
            $this->userID = intval($this->getSessionUID($this->getSessionHash()));
            return $this->userID;
        }
        return 0;
    }
    
    /**
     * Returns the user IP Address
     * @return string This will be the users IP address
     */
    public function getUserIP()
    {
        return $this->getIp();
    }

    /**
     * Returns the users email address if the user is logged in
     * @return string This should be the users IP address if the user is logged in
     */
    public function getUserEmail()
    {
        if (!isset($this->userInfo)) {
            $this->getUserInfo();
        }
        return $this->userInfo['email'];
    }
}
