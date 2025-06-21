
-- ====================================================
-- Password Reset & Email Verification System (MySQL 8.0+)
-- DevifyX Assignment - Full Version with Bonus Features
-- Author: Your Name
-- Description: Implements user authentication recovery logic with:
--  - Email verification
--  - Password reset
--  - Audit trail
--  - Token expiry logic
--  - Bonus: Rate limiting, multi-use tokens, auto cleanup
-- ====================================================

-- ========== USERS ==========
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    is_verified BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ========== EMAIL VERIFICATIONS ==========
CREATE TABLE email_verifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    expiry_time DATETIME NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    use_count INT DEFAULT 0,
    max_uses INT DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ========== PASSWORD RESETS ==========
CREATE TABLE password_resets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    expiry_time DATETIME NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    use_count INT DEFAULT 0,
    max_uses INT DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ========== AUDIT LOG ==========
CREATE TABLE audit_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action_type VARCHAR(50),
    description TEXT,
    action_time DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ========== RATE LIMIT LOG ==========
CREATE TABLE request_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    action_type ENUM('email_verification', 'password_reset'),
    request_time DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ========== FUNCTION: GENERATE TOKEN ==========
DELIMITER //
CREATE FUNCTION generate_token()
RETURNS VARCHAR(255)
DETERMINISTIC
BEGIN
    RETURN UUID();
END;
//
DELIMITER ;

-- ========== PROCEDURE: CHECK RATE LIMIT ==========
DELIMITER //
CREATE PROCEDURE check_rate_limit(IN uid INT, IN action VARCHAR(50), OUT is_allowed BOOLEAN)
BEGIN
    DECLARE req_count INT;

    SELECT COUNT(*) INTO req_count
    FROM request_log
    WHERE user_id = uid AND action_type = action AND request_time >= NOW() - INTERVAL 1 HOUR;

    SET is_allowed = (req_count < 3);
END;
//
DELIMITER ;

-- ========== PROCEDURE: INITIATE EMAIL VERIFICATION ==========
DELIMITER //
CREATE PROCEDURE initiate_email_verification(IN uid INT)
BEGIN
    DECLARE tok VARCHAR(255);
    DECLARE allowed BOOLEAN;

    CALL check_rate_limit(uid, 'email_verification', allowed);
    IF allowed THEN
        SET tok = generate_token();
        INSERT INTO email_verifications (user_id, token, expiry_time, max_uses)
        VALUES (uid, tok, NOW() + INTERVAL 30 MINUTE, 3);

        UPDATE users SET is_verified = FALSE WHERE id = uid;

        INSERT INTO audit_log (user_id, action_type, description)
        VALUES (uid, 'email_verification', CONCAT('Verification token: ', tok));

        INSERT INTO request_log (user_id, action_type) VALUES (uid, 'email_verification');
    END IF;
END;
//
DELIMITER ;

-- ========== PROCEDURE: VERIFY EMAIL ==========
DELIMITER //
CREATE PROCEDURE verify_email(IN tok VARCHAR(255))
BEGIN
    DECLARE uid INT;

    SELECT user_id INTO uid
    FROM email_verifications
    WHERE token = tok AND is_used = FALSE AND expiry_time > NOW() AND use_count < max_uses
    LIMIT 1;

    IF uid IS NOT NULL THEN
        UPDATE email_verifications SET use_count = use_count + 1 WHERE token = tok;
        UPDATE users SET is_verified = TRUE WHERE id = uid;

        IF (SELECT use_count FROM email_verifications WHERE token = tok) >= max_uses THEN
            UPDATE email_verifications SET is_used = TRUE WHERE token = tok;
        END IF;

        INSERT INTO audit_log (user_id, action_type, description)
        VALUES (uid, 'email_verification', 'Email verified.');
    END IF;
END;
//
DELIMITER ;

-- ========== PROCEDURE: INITIATE PASSWORD RESET ==========
DELIMITER //
CREATE PROCEDURE initiate_password_reset(IN uid INT)
BEGIN
    DECLARE tok VARCHAR(255);
    DECLARE allowed BOOLEAN;

    CALL check_rate_limit(uid, 'password_reset', allowed);
    IF allowed THEN
        SET tok = generate_token();
        INSERT INTO password_resets (user_id, token, expiry_time, max_uses)
        VALUES (uid, tok, NOW() + INTERVAL 30 MINUTE, 3);

        INSERT INTO audit_log (user_id, action_type, description)
        VALUES (uid, 'password_reset', CONCAT('Reset token: ', tok));

        INSERT INTO request_log (user_id, action_type) VALUES (uid, 'password_reset');
    END IF;
END;
//
DELIMITER ;

-- ========== PROCEDURE: RESET PASSWORD ==========
DELIMITER //
CREATE PROCEDURE reset_password(IN tok VARCHAR(255), IN new_pass VARCHAR(255))
BEGIN
    DECLARE uid INT;

    SELECT user_id INTO uid
    FROM password_resets
    WHERE token = tok AND is_used = FALSE AND expiry_time > NOW() AND use_count < max_uses
    LIMIT 1;

    IF uid IS NOT NULL THEN
        UPDATE password_resets SET use_count = use_count + 1 WHERE token = tok;
        UPDATE users SET password_hash = new_pass WHERE id = uid;

        IF (SELECT use_count FROM password_resets WHERE token = tok) >= max_uses THEN
            UPDATE password_resets SET is_used = TRUE WHERE token = tok;
        END IF;

        INSERT INTO audit_log (user_id, action_type, description)
        VALUES (uid, 'password_reset', 'Password reset.');
    END IF;
END;
//
DELIMITER ;

-- ========== EVENT: AUTO CLEANUP ==========
DELIMITER //
CREATE EVENT IF NOT EXISTS cleanup_expired
ON SCHEDULE EVERY 1 HOUR
DO
BEGIN
    DELETE FROM email_verifications WHERE expiry_time < NOW() AND is_used = FALSE;
    DELETE FROM password_resets WHERE expiry_time < NOW() AND is_used = FALSE;
    DELETE FROM request_log WHERE request_time < NOW() - INTERVAL 2 DAY;
END;
//
DELIMITER ;

-- ========== SAMPLE DATA ==========
INSERT INTO users (email, password_hash) VALUES
('alexa@gmail.com', 'password_123'),
('siri@gmail.com', 'password_1234');


