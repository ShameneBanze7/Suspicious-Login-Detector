# Suspicious Login Detector

## What is this?
Have you ever wondered how systems catch hackers trying to break in? This project acts as a "security guard" for a login system. 

It watches every login attempt and looks for sketchy behaviour—like someone trying ten different passwords in a row, or a user suddenly logging in from a random IP address at 3 AM. When it spots a pattern that looks wrong, it raises an alarm, scores the risk, and tells you exactly *why* it's suspicious. 

## How does it work? (The Rules)
Instead of just blocking people, the system gives every login attempt a "risk score." It looks at a few specific clues, and if the score gets high enough, it flags the account.

Here are the rules I built:
*   **A failed attempt:** Add +1 point. (Failures are normal, but they add up).
*   **A brand new IP address:** Add +2 points. (If a user from New York suddenly logs in from Russia, that's weird).
*   **Logging in at an odd hour:** Add +2 points. (Say, between midnight and 5 AM, when normal users are asleep).
*   **Success right after a bunch of failures:** Add +5 points. (This is the big one. It often means the attacker finally guessed the password).

**The Risk Levels:**
*   **0 to 2 points:** Normal. No worries.
*   **3 to 4 points:** Suspicious. Keep an eye on this one.
*   **5 or more points:** High Risk. Time to investigate or block the account.

## The Database (Table Design)
To keep track of everything, every single login attempt (whether it works or fails) gets saved to a database table. Failures are actually the most important data we have!

I upgraded this project to use **MySQL** to make it feel like a real-world application. I created the table directly in MySQL Workbench using this schema:

```sql
CREATE TABLE login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    success BOOLEAN NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    risk_level VARCHAR(20) DEFAULT 'Pending',
    reason VARCHAR(255) DEFAULT NULL
);
