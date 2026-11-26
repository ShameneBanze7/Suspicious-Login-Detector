/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package com.mycompany.suspiciouslogindetector;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * The LoginDetector class reads recent login attempts from the database and applies 
 * a set of security rules to determine the risk level of each login.
 * 
 * I separated each rule into its own method so they are easy to test, maintain, and explain.
 */
public class LoginDetector {

    // MySQL Database Connection Credentials
    private static final String URL = "jdbc:mysql://localhost:3306/login_security"; // Local database URL
    private static final String USER = "root";                                      // MySQL username
    private static final String PASSWORD = "Comeonprompt0707!";                     // MySQL password
    
    public static void main(String[] args) {
        System.out.println("--- Starting Security Analysis ---");
        // Call the main analysis method
        analyzeLogins();
        System.out.println("--- Analysis Complete ---");
    }

    /**
     * The core engine that loops through unchecked logins and applies the rules.
     */
    public static void analyzeLogins() {
        // I only want to analyze attempts that have a 'Pending' status.
        // This ensures I don't re-analyze logs that have already been processed.
        String selectSQL = "SELECT id, username, success, ip_address, attempt_time FROM login_attempts WHERE risk_level = 'Pending'";

        // try-with-resources automatically closes the database connection and statements
        // I added USER and PASSWORD here so it can connect to MySQL
        try (Connection conn = DriverManager.getConnection(URL, USER, PASSWORD);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(selectSQL)) {

            // Loop through each pending login attempt
            while (rs.next()) {
                // Extract data from the current row
                int id = rs.getInt("id");
                String username = rs.getString("username");
                boolean success = rs.getBoolean("success"); // MySQL uses boolean (true/false)
                String ipAddress = rs.getString("ip_address");
                String attemptTime = rs.getString("attempt_time");

                // Initialize the risk score and a list to store the reasons
                int score = 0;
                StringBuilder reasons = new StringBuilder();

                // --- APPLY RULES ---
                
                // Rule 1: Any failed attempt adds a base score of 1 point
                if (!success) {
                    score += 1;
                    reasons.append("Failed attempt. ");
                }

                // Rule 2: Check if this user has 5+ rapid failures in the last 10 minutes (+5 points)
                if (checkFailedAttempts(conn, username, attemptTime)) {
                    score += 5;
                    reasons.append("Suspicious: 5+ failures within 10 minutes. ");
                }

                // Rule 3: Check if a successful login is coming from an unknown IP (+2 points)
                if (success && checkNewIp(conn, username, ipAddress, id)) {
                    score += 2;
                    reasons.append("New IP address for this user. ");
                }

                // Rule 4: Check if the login happened during odd hours (+2 points)
                if (checkOddTime(attemptTime)) {
                    score += 2;
                    reasons.append("Odd login hour. ");
                }

                // Determine the Risk Level based on the final accumulated score
                String riskLevel = "Normal";
                if (score >= 5) {
                    riskLevel = "High Risk";
                } else if (score >= 3) {
                    riskLevel = "Suspicious";
                }

                // Update the database with the calculated risk level and reasons
                // I added 'username' to the parameters so it prints correctly in the console
                updateRiskLevel(conn, id, username, riskLevel, reasons.toString().trim());
            }

        } catch (SQLException e) {
            System.out.println("Error analyzing logins: " + e.getMessage());
        }
    }

    // ==========================================
    //            RULE METHODS
    // ==========================================

    /**
     * Rule 1: Checks if there are 5 or more failures within a 10-minute window.
     * This detects rapid, brute-force password guessing attacks.
     */
    private static boolean checkFailedAttempts(Connection conn, String username, String currentTime) {
        // I updated this query to use MySQL's INTERVAL syntax instead of SQLite's datetime() function
        String query = "SELECT COUNT(*) as fail_count FROM login_attempts " +
                       "WHERE username = ? AND success = false AND attempt_time >= (TIMESTAMP(?) - INTERVAL 10 MINUTE)";
        
        try (PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setString(1, username);
            pstmt.setString(2, currentTime);
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                // If we find 5 or more failures in that window, trigger the rule
                return rs.getInt("fail_count") >= 5;
            }
        } catch (SQLException e) {
            System.out.println("Error in checkFailedAttempts: " + e.getMessage());
        }
        return false;
    }

    /**
     * Rule 2: Checks if a successful login is coming from an IP the user hasn't used before.
     * This detects account takeovers where a hacker logs in from a new location.
     */
    private static boolean checkNewIp(Connection conn, String username, String currentIp, int currentId) {
        // We look for any PREVIOUS successful logins from this user with this IP address
        // I changed 'success = 1' to 'success = true' for MySQL
        String query = "SELECT COUNT(*) as ip_count FROM login_attempts " +
                       "WHERE username = ? AND ip_address = ? AND success = true AND id < ?";
        
        try (PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setString(1, username);
            pstmt.setString(2, currentIp);
            pstmt.setInt(3, currentId);
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                // If the count is 0, it means we found NO previous successful logins from this IP.
                return rs.getInt("ip_count") == 0;
            }
        } catch (SQLException e) {
            System.out.println("Error in checkNewIp: " + e.getMessage());
        }
        return false;
    }

    /**
     * Rule 3: Checks if the login happened during odd hours (midnight to 5 AM).
     * Attackers often strike when users and IT staff are asleep.
     */
    private static boolean checkOddTime(String attemptTime) {
        try {
            // attempt_time format is "YYYY-MM-DD HH:MM:SS"
            // We extract the hour (characters at index 11 and 12)
            int hour = Integer.parseInt(attemptTime.substring(11, 13));
            return (hour >= 0 && hour <= 5); 
        } catch (Exception e) {
            return false; 
        }
    }

    /**
     * Updates the database row with the calculated risk level and reasons.
     */
    private static void updateRiskLevel(Connection conn, int id, String username, String riskLevel, String reason) {
        String updateSQL = "UPDATE login_attempts SET risk_level = ?, reason = ? WHERE id = ?";
        
        try (PreparedStatement pstmt = conn.prepareStatement(updateSQL)) {
            pstmt.setString(1, riskLevel);
            pstmt.setString(2, reason);
            pstmt.setInt(3, id);
            pstmt.executeUpdate();
            
            // Only print to the console if the attempt was flagged as suspicious or high risk
            if (!riskLevel.equals("Normal")) {
                System.out.println("Flagged ID " + id + " (" + username + "): " + riskLevel + " -> " + reason);
            }
            
        } catch (SQLException e) {
            System.out.println("Error updating risk level: " + e.getMessage());
        }
    }
}