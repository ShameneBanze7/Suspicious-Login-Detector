/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.mycompany.suspiciouslogindetector;

// Import the JDBC classes required for database connection and querying
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Queries the database and prints a formatted report of all flagged 
 * (Suspicious or High Risk) login attempts.
 */
public class ReportGenerator {
    
    // The connection string for the local SQLite database file
    private static final String URL = "jdbc:sqlite:logins.db";

    public static void main(String[] args) {
        // Print a header for the report so it looks clean in the console
        System.out.println("=========================================");
        System.out.println("     FLAGGED SECURITY REPORT");
        System.out.println("=========================================");

        // The SQL query filters out 'Normal' and 'Pending' attempts.
        // We use ORDER BY risk_level DESC to ensure 'High Risk' shows up before 'Suspicious'.
       String query = "SELECT username, ip_address, attempt_time, risk_level, reason FROM login_attempts WHERE risk_level != 'Normal' AND risk_level != 'Pending' GROUP BY username, risk_level ORDER BY risk_level DESC";
        // We use a try-with-resources block. This automatically closes the Connection, 
        // Statement, and ResultSet when the block finishes, preventing memory leaks.
        try (Connection conn = DriverManager.getConnection(URL);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {

            // A flag to check if the query found any flagged rows. 
            // If it remains false, we know the system is safe.
            boolean foundAny = false;
            
            // Loop through each row returned by the database
            while (rs.next()) {
                foundAny = true;
                
                // Extract data from the current row using the column names
                System.out.println("User: " + rs.getString("username") + " | IP: " + rs.getString("ip_address"));
                System.out.println("Time: " + rs.getString("attempt_time"));
                System.out.println("Risk: [" + rs.getString("risk_level") + "]");
                System.out.println("Why:  " + rs.getString("reason"));
                System.out.println("-----------------------------------------");
            }
            
            // If the loop finished and foundAny is still false, no threats were detected
            if (!foundAny) {
                System.out.println("No suspicious activity found. All systems normal.");
            }

        } catch (SQLException e) {
            // Catch any database errors (e.g., file missing or table missing)
            System.out.println("Error generating report: " + e.getMessage());
        }
    }
}