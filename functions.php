<?php

if(!function_exists('sendEmail')){
    /**
     * This function sends the email and returns true or false as to status
     * @param string $to This should be the email address of the person you wish to send the email to
     * @param string $subject The subject of the email message
     * @param string $plain The plain text version of the email message
     * @param string $html The HTML version of the email message
     * @param string $from The email address of the person the email is from
     * @param string $fromname The name of the person the email is from
     * @param string $replyto If you want to change the reply to address
     * @param array $attachment A single attachment should be included here e.g. array(path, name, encoding = base64, mimetype)
     * @return true|false Returns true if email sent else returns false 
     */
    function sendEmail($to, $subject, $plain, $html, $from, $fromname, $replyto = '', $attachment = ''){
        // Check configuration for SMTP parameters
        $mail = new PHPMailer\PHPMailer\PHPMailer();
        $mail->CharSet = 'UTF-8';
        if(USE_SMTP){
            $mail->isSMTP();
            $mail->Host = SMTP_HOST;
            $mail->SMTPAuth = SMTP_AUTH;
            if(!is_null(SMTP_AUTH)){
                $mail->Username = SMTP_USERNAME;
                $mail->Password = SMTP_PASSWORD;
            }
            $mail->Port = SMTP_PORT;
            if(!is_null(SMTP_SECURITY)){
                $mail->SMTPSecure = SMTP_SECURITY;
            }
        }
        
        $mail->From = $from;
        $mail->FromName = $fromname;
        if(!empty($replyto)){
            $mail->AddReplyTo($replyto, $fromname);
        }
        $mail->addAddress($to);
        $mail->isHTML(true);
        if(!empty($attachment)){
            $mail->addAttachment($attachment[0], $attachment[1], $attachment[2], $attachment[3]);
        }
        $mail->Subject = $subject;
        $mail->Body = $html;
        $mail->AltBody = $plain;
        return $mail->send();
    }
}