DROP TABLE IF EXISTS `attempts`;
CREATE TABLE IF NOT EXISTS `attempts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ip` varchar(39) NOT NULL,
  `expirydate` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

DROP TABLE IF EXISTS `requests`;
CREATE TABLE IF NOT EXISTS `requests` (
  `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `uid` int(11) UNSIGNED NOT NULL,
  `rkey` varchar(20) NOT NULL,
  `expire` datetime NOT NULL,
  `type` varchar(20) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `uid` (`uid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

DROP TABLE IF EXISTS `sessions`;
CREATE TABLE IF NOT EXISTS `sessions` (
  `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `uid` int(11) UNSIGNED NOT NULL,
  `hash` varchar(40) NOT NULL,
  `expiredate` datetime NOT NULL,
  `ip` varchar(39) NOT NULL,
  `agent` varchar(200) NOT NULL,
  `cookie_crc` varchar(40) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `uid` (`uid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

DROP TABLE IF EXISTS `users`;
CREATE TABLE IF NOT EXISTS `users` (
  `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `email` varchar(100) DEFAULT NULL,
  `password` varchar(60) DEFAULT NULL,
  `isactive` tinyint(1) NOT NULL DEFAULT '0',
  `dt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `last_login` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

ALTER TABLE `requests`
  ADD CONSTRAINT `requests_ibfk_1` FOREIGN KEY (`uid`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `sessions`
  ADD CONSTRAINT `sessions_ibfk_1` FOREIGN KEY (`uid`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;