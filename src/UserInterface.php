<?php
interface UserInterface{
    public function __construct($db, $config, $language = "en_GB");
    public function login($email, $password, $remember = 0, $captcha = NULL);
    public function register($email, $password, $repeatpassword, $params = array(), $captcha = NULL, $sendmail = NULL);
    public function activate($key);
    public function requestReset($email, $sendmail = NULL);
    public function logout($hash);
    public function getHash($password);
    public function getUID($email);
    public function addSession($uid, $remember);
    public function checkSession($hash);
    public function getSessionUID($hash);
    public function isEmailTaken($email);
    public function getUser($uid);
    public function deleteUser($uid, $password, $captcha = NULL);
    public function getRequest($key, $type);
    public function resetPass($key, $password, $repeatpassword, $captcha = NULL);
    public function resendActivation($email, $sendmail = NULL);
    public function changePassword($uid, $currpass, $newpass, $repeatnewpass, $captcha = NULL);
    public function changeEmail($uid, $email, $password, $captcha = NULL);
    public function isBlocked();
    public function getRandomKey($length = 20);
    public function isLogged();
    public function getSessionHash();
    public function comparePasswords($userid, $password_for_check);
    
    // Adams functions
    public function getUserID();
    public function getUserIP();
    public function getUserEmail();
    public function getUserInfo();
    public function getFirstname();
    public function getLastname();
    public function getUserSettings();
    public function setUserSettings($vars);
}
