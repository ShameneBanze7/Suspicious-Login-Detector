/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package com.mycompany.suspiciouslogindetector;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

/**
 * This class simulates edge cases to prove that the detector logic is robust.
 * It specifically tests the boundaries of the "Failed Attempts" rule.
 */
public class EdgeCaseTester {
    
       // MySQL Database Connection Credentials
    private static final String URL = "jdbc:mysql://localhost:3306/login_security"; // Local database URL
    private static final String USER = "root";                                      // MySQL username
    private static final String PASSWORD = "Comeonprompt0707!";                   // MySQL password
    
    public static void main(String[] args) {
        System.out.println("--- Inserting Edge Case Test Data ---");
        
        // We use a try-with-resources block to open the database connection.
        // It will automatically close the connection when the block finishes.
        try (Connection conn = DriverManager.getConnection(URL)) {
            
            // CASE 1: Exactly 4 failures in a short time. 
            // The rule triggers at 5, so this should remain "Normal" (Score: 1 for each failure, but no +5 penalty).
            insertAttempts(conn, "edgecase_4fails", 0, "192.168.1.50", 4);
            
            // CASE 2: Exactly 5 failures in a short time.
            // The rule triggers at 5, so this should be flagged as "High Risk" (+5 penalty).
            insertAttempts(conn, "edgecase_5fails", 0, "192.168.1.50", 5);
            
            // CASE 3: 5 failures, but spaced 30 minutes apart.
            // Even though there are 5 failures, they are not within a 10-minute window, 
            // so the rapid attack rule should NOT trigger.
            insertAttemptsWithDelay(conn, "edgecase_delayed", 0, "192.168.1.50", 5);
            
            System.out.println("Edge case data inserted successfully.");
            System.out.println("Now run LoginDetector.java to analyze them!");
            
        } catch (SQLException e) {
            System.out.println("Database error: " + e.getMessage());
        }
    }

    /**
     * Helper method to insert a specific number of failed attempts all at once.
     * 
     * @param conn The active database connection.
     * @param username The user failing the login.
     * @param success 0 for failed login.
     * @param ip The IP address making the attempt.
     * @param count The number of attempts to insert.
     */
    private static void insertAttempts(Connection conn, String username, int success, String ip, int count) throws SQLException {
        String sql = "INSERT INTO login_attempts(username, success, ip_address) VALUES(?, ?, ?)";
        
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            // Loop 'count' times to insert multiple rows
            for (int i = 0; i < count; i++) {
                pstmt.setString(1, username);
                pstmt.setInt(2, success);
                pstmt.setString(3, ip);
                pstmt.executeUpdate();
            }
        }
    }

    /**
     * Helper method to insert attempts with a simulated time delay.
     * This tests if our detector correctly ignores failures that are spread out over time.
     */
    private static void insertAttemptsWithDelay(Connection conn, String username, int success, String ip, int count) throws SQLException {
        // We use SQLite's date math function to insert rows into the PAST.
        // datetime('now', '-30 minutes') will make the attempt look like it happened 30 mins ago.
        String sql = "INSERT INTO login_attempts(username, success, ip_address, attempt_time) VALUES(?, ?, ?, datetime('now', '-' || ? || ' minutes'))";
        
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            for (int i = 0; i < count; i++) {
                // Spaces the attempts out by 30, 60, 90, 120, and 150 minutes into the past
                int minutesAgo = (i + 1) * 30; 
                
                pstmt.setString(1, username);
                pstmt.setInt(2, success);
                pstmt.setString(3, ip);
                pstmt.setInt(4, minutesAgo); // Injects the calculated minutes
                pstmt.executeUpdate();
            }
        }
    }
}