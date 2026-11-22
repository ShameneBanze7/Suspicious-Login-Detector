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
 * The LoginDetector class reads recent attempts from the database and applies 
 * security rules to determine the risk level of each login.
 */
public class LoginDetector {

    private static final String URL = "jdbc:sqlite:logins.db";

    public static void main(String[] args) {
        System.out.println("--- Starting Security Analysis ---");
        analyzeLogins();
        System.out.println("--- Analysis Complete ---");
    }

    public static void analyzeLogins() {
        // We only analyze attempts that haven't been checked yet (Pending)
        String selectSQL = "SELECT id, username, success, ip_address, attempt_time FROM login_attempts WHERE risk_level = 'Pending'";

        try (Connection conn = DriverManager.getConnection(URL);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(selectSQL)) {

            while (rs.next()) {
                int id = rs.getInt("id");
                String username = rs.getString("username");
                boolean success = rs.getInt("success") == 1;
                String ipAddress = rs.getString("ip_address");
                String attemptTime = rs.getString("attempt_time");

                int score = 0;
                StringBuilder reasons = new StringBuilder();

                // --- APPLY RULES ---
                
                // Rule 1: Failed attempt (+1 point)
                if (!success) {
                    score += 1;
                    reasons.append("Failed attempt. ");
                }

                // Rule 2: Check for rapid failures (5+ failures in 10 mins) (+5 points)
                if (checkFailedAttempts(conn, username, attemptTime)) {
                    score += 5;
                    reasons.append("Suspicious: 5+ failures within 10 minutes. ");
                }

                // Rule 3: Check for New IP Address on a successful login (+2 points)
                if (success && checkNewIp(conn, username, ipAddress, id)) {
                    score += 2;
                    reasons.append("New IP address for this user. ");
                }

                // Rule 4: Odd login time (+2 points)
                if (checkOddTime(attemptTime)) {
                    score += 2;
                    reasons.append("Odd login hour. ");
                }

                // Determine Risk Level based on score
                String riskLevel = "Normal";
                if (score >= 5) {
                    riskLevel = "High Risk";
                } else if (score >= 3) {
                    riskLevel = "Suspicious";
                }

                // Update the database with the findings
                updateRiskLevel(conn, id, riskLevel, reasons.toString().trim());
            }

        } catch (SQLException e) {
            System.out.println("Error analyzing logins: " + e.getMessage());
        }
    }

    // --- RULE METHODS ---

    /**
     * Rule 1: Checks if there are 5 or more failures in a short time window.
     */
    private static boolean checkFailedAttempts(Connection conn, String username, String currentTime) {
        String query = "SELECT COUNT(*) as fail_count FROM login_attempts " +
                       "WHERE username = ? AND success = 0 AND attempt_time >= datetime(?, '-10 minutes')";
        
        try (PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setString(1, username);
            pstmt.setString(2, currentTime);
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                return rs.getInt("fail_count") >= 5;
            }
        } catch (SQLException e) {
            System.out.println("Error in checkFailedAttempts: " + e.getMessage());
        }
        return false;
    }

    /**
     * Rule 2: Checks if a successful login is coming from an IP the user hasn't used before.
     */
    private static boolean checkNewIp(Connection conn, String username, String currentIp, int currentId) {
        String query = "SELECT COUNT(*) as ip_count FROM login_attempts " +
                       "WHERE username = ? AND ip_address = ? AND success = 1 AND id < ?";
        
        try (PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setString(1, username);
            pstmt.setString(2, currentIp);
            pstmt.setInt(3, currentId);
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                return rs.getInt("ip_count") == 0;
            }
        } catch (SQLException e) {
            System.out.println("Error in checkNewIp: " + e.getMessage());
        }
        return false;
    }

    /**
     * Rule 3: Checks if the login happened during odd hours (12 AM to 5 AM).
     */
    private static boolean checkOddTime(String attemptTime) {
        try {
            // attempt_time format is usually "YYYY-MM-DD HH:MM:SS"
            int hour = Integer.parseInt(attemptTime.substring(11, 13));
            return (hour >= 0 && hour <= 5); 
        } catch (Exception e) {
            return false; 
        }
    }

    /**
     * Updates the database row with the calculated risk level and reasons.
     */
    private static void updateRiskLevel(Connection conn, int id, String riskLevel, String reason) {
        String updateSQL = "UPDATE login_attempts SET risk_level = ?, reason = ? WHERE id = ?";
        
        try (PreparedStatement pstmt = conn.prepareStatement(updateSQL)) {
            pstmt.setString(1, riskLevel);
            pstmt.setString(2, reason);
            pstmt.setInt(3, id);
            pstmt.executeUpdate();
            
            // Only print if it found something interesting
            if (!riskLevel.equals("Normal")) {
                String username = null;
                System.out.println("Flagged ID " + id + " (" + username + "): " + riskLevel + " -> " + reason);
            }
            
        } catch (SQLException e) {
            System.out.println("Error updating risk level: " + e.getMessage());
        }
    }
}