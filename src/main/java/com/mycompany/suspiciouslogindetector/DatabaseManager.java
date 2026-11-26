/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */

package com.mycompany.suspiciouslogindetector;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * The DatabaseManager class is responsible for setting up the local database.
 * It creates the necessary tables and populates them with initial test data 
 * so we can test the suspicious login detection logic.
 */
public class DatabaseManager {

    // MySQL Database Connection Credentials
    private static final String URL = "jdbc:mysql://localhost:3306/login_security"; // Local database URL
    private static final String USER = "root";                                      // MySQL username
    private static final String PASSWORD = "Comeonprompt0707!";                   // MySQL password

    /**
     * The main method acts as the entry point for our database setup script.
     */
    public static void main(String[] args) {
        // 1. Create the table if it doesn't already exist
        createTable();

        // 2. Insert fake data to simulate various login scenarios
        insertFakeData();
        
        System.out.println("Database setup and fake data insertion complete!");
    }

    /**
     * Creates the 'login_attempts' table in the database.
     * I used "IF NOT EXISTS" so that running this script multiple times doesn't crash.
     */
    public static void createTable() {
        // The SQL query defines the structure of our security log.
        // I updated this to use MySQL syntax (INT AUTO_INCREMENT and BOOLEAN).
        String createTableSQL = "CREATE TABLE IF NOT EXISTS login_attempts ("
                + "id INT AUTO_INCREMENT PRIMARY KEY, "     // Unique ID for every single attempt
                + "username VARCHAR(50) NOT NULL, "         // Who tried to log in
                + "success BOOLEAN NOT NULL, "              // Did it work? (true/false in MySQL)
                + "ip_address VARCHAR(45) NOT NULL, "       // Where did they try to log in from
                + "attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " // Automatically logs the exact time
                + "risk_level VARCHAR(20) DEFAULT 'Pending', "    // Will be updated by the detector later
                + "reason VARCHAR(255) DEFAULT NULL"               // Will store the reason for the flag later
                + ");";

        // Using a try-with-resources block ensures the database connection 
        // and statement are closed automatically, preventing memory leaks.
        // I added USER and PASSWORD to the getConnection method for MySQL.
        try (Connection conn = DriverManager.getConnection(URL, USER, PASSWORD);
             Statement stmt = conn.createStatement()) {
            
            // Execute the SQL query to build the table
            stmt.execute(createTableSQL);
            System.out.println("Table 'login_attempts' created successfully.");
            
        } catch (SQLException e) {
            // If something goes wrong (like a locked database), print the error
            System.out.println("Error creating table: " + e.getMessage());
        }
    }

    /**
     * Inserts fake data into the database to test our security rules.
     * I used a PreparedStatement here instead of a regular Statement because 
     * it prevents SQL Injection attacks and is much faster for multiple inserts.
     */
    public static void insertFakeData() {
        // The '?' are placeholders where we will inject our variables safely
        String insertSQL = "INSERT INTO login_attempts(username, success, ip_address) VALUES(?, ?, ?)";
        
        // i passed URL, USER, and PASSWORD to the getConnection method now
        try (Connection conn = DriverManager.getConnection(URL, USER, PASSWORD);
             PreparedStatement pstmt = conn.prepareStatement(insertSQL)) {
            
            // --- Scenario 1: A classic password-guessing attack ---
            // Inserting 6 rapid failures for "testuser" to trigger our "Too many failed attempts" rule.
            for (int i = 0; i < 6; i++) {
                pstmt.setString(1, "testuser");        // Username
                pstmt.setBoolean(2, false);            // false = failed login (MySQL boolean)
                pstmt.setString(3, "192.168.1.100");   // A suspicious IP
                pstmt.executeUpdate();                 // Push the row to the database
            }
            System.out.println("Inserted 6 failed attempts for 'testuser'.");

            // --- Scenario 2: A completely normal user ---
            // A successful login during the day from a normal IP. 
            // This is our "control" test to make sure our detector doesn't flag everything.
            pstmt.setString(1, "normal_user");
            pstmt.setBoolean(2, true);                 // true = successful login
            pstmt.setString(3, "10.0.0.5");
            pstmt.executeUpdate();
            System.out.println("Inserted 1 successful attempt for 'normal_user'.");
            
            // --- Scenario 3: Setting up a historical known IP for a user ---
            // This is necessary so we can test the "New IP Address" rule later. 
            // If alice logs in from 10.0.0.99 now, and then later from a different IP, the detector will catch it.
            pstmt.setString(1, "Alice");
            pstmt.setBoolean(2, true);                 // true = successful login
            pstmt.setString(3, "10.0.0.99");           // alice's normal, known IP
            pstmt.executeUpdate();
            System.out.println("Inserted historical login for 'alice' (Known IP).");

        } catch (SQLException e) {
            System.out.println("Error inserting data: " + e.getMessage());
        }
    }
}