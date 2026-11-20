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

    // I are using SQLite for easy local setup because it doesn't require a server.
    // This connection string will automatically create a file named 'logins.db' in the project root.
    private static final String URL = "jdbc:sqlite:logins.db";

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
     * I use "IF NOT EXISTS" so that running this script multiple times doesn't crash.
     */
    public static void createTable() {
        // The SQL query defines the structure of our security log.
        String createTableSQL = "CREATE TABLE IF NOT EXISTS login_attempts ("
                + "id INTEGER PRIMARY KEY AUTOINCREMENT, " // Unique ID for every single attempt
                + "username TEXT NOT NULL, "               // Who tried to log in
                + "success INTEGER NOT NULL, "             // Did it work? (1 for true, 0 for false in SQLite)
                + "ip_address TEXT NOT NULL, "             // Where did they try to log in from
                + "attempt_time TEXT DEFAULT CURRENT_TIMESTAMP, " // Automatically logs the exact time
                + "risk_level TEXT DEFAULT 'Pending', "    // Will be updated by the detector later
                + "reason TEXT DEFAULT NULL"               // Will store the reason for the flag later
                + ");";

        // Using a try-with-resources block ensures the database connection 
        // and statement are closed automatically, preventing memory leaks.
        try (Connection conn = DriverManager.getConnection(URL);
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
     * I use a PreparedStatement here instead of a regular Statement because 
     * it prevents SQL Injection attacks and is much faster for multiple inserts.
     */
    public static void insertFakeData() {
        // The '?' are placeholders where we will inject our variables safely
        String insertSQL = "INSERT INTO login_attempts(username, success, ip_address) VALUES(?, ?, ?)";

        try (Connection conn = DriverManager.getConnection(URL);
             PreparedStatement pstmt = conn.prepareStatement(insertSQL)) {

            // --- Scenario 1: A classic password-guessing attack ---
            // Inserting 6 rapid failures for "testuser" to trigger our "Too many failed attempts" rule.
            for (int i = 0; i < 6; i++) {
                pstmt.setString(1, "testuser");        // Username
                pstmt.setInt(2, 0);                    // 0 = false (failed login)
                pstmt.setString(3, "192.168.1.100");   // A suspicious IP
                pstmt.executeUpdate();                 // Push the row to the database
            }
            System.out.println("Inserted 6 failed attempts for 'testuser'.");

            // --- Scenario 2: A completely normal user ---
            // A successful login during the day from a normal IP. 
            // This is our "control" test to make sure our detector doesn't flag everything.
            pstmt.setString(1, "normal_user");
            pstmt.setInt(2, 1);                        // 1 = true (success)
            pstmt.setString(3, "10.0.0.5");
            pstmt.executeUpdate();
            System.out.println("Inserted 1 successful attempt for 'normal_user'.");

        } catch (SQLException e) {
            System.out.println("Error inserting data: " + e.getMessage());
        }
    }
}