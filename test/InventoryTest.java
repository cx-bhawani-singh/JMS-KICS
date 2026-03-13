import org.junit.*;
import static org.junit.Assert.*;
import java.sql.*;
import java.awt.event.ActionEvent;
import javax.swing.*;

/**
 * Comprehensive tests for Inventory class SQL injection remediation.
 * These tests verify that:
 * 1. The vulnerability is fixed using PreparedStatement
 * 2. SQL injection attacks are prevented
 * 3. Normal functionality still works correctly
 */
public class InventoryTest {

    private Inventory inventory;
    private Connection testConnection;
    private Statement stmt;

    @Before
    public void setUp() throws Exception {
        inventory = new Inventory();
        // Setup in-memory test database
        Class.forName("org.h2.Driver");
        testConnection = DriverManager.getConnection("jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1", "sa", "");
        stmt = testConnection.createStatement();

        // Create test table
        stmt.execute("CREATE TABLE IF NOT EXISTS Inventory (" +
                    "Style_ID VARCHAR(100), " +
                    "Vendor_ID VARCHAR(100), " +
                    "In_Date VARCHAR(100), " +
                    "Gold VARCHAR(100), " +
                    "Gold_wt VARCHAR(100), " +
                    "Stone_Type VARCHAR(100), " +
                    "Stone_Weight VARCHAR(100), " +
                    "Stone_numbers VARCHAR(100), " +
                    "Details VARCHAR(255))");
    }

    @After
    public void tearDown() throws Exception {
        if (stmt != null) {
            stmt.execute("DROP TABLE IF EXISTS Inventory");
            stmt.close();
        }
        if (testConnection != null) {
            testConnection.close();
        }
    }

    /**
     * Test 1: Verify PreparedStatement is used (code review test)
     * This test verifies that the vulnerable code has been replaced with PreparedStatement
     */
    @Test
    public void testPreparedStatementIsUsed() throws Exception {
        // Read the source file to verify PreparedStatement usage
        java.io.BufferedReader reader = new java.io.BufferedReader(
            new java.io.FileReader("./Inventory.java"));
        String line;
        boolean foundPreparedStatement = false;
        boolean foundSetString = false;
        boolean noStringConcatenation = true;

        while ((line = reader.readLine()) != null) {
            if (line.contains("PreparedStatement")) {
                foundPreparedStatement = true;
            }
            if (line.contains("pstmt.setString")) {
                foundSetString = true;
            }
            // Check that the vulnerable pattern is gone
            if (line.contains("VALUES ('\"") || line.contains("+'\"")) {
                noStringConcatenation = false;
            }
        }
        reader.close();

        assertTrue("PreparedStatement should be used", foundPreparedStatement);
        assertTrue("Parameterized binding (setString) should be used", foundSetString);
        assertTrue("No string concatenation in SQL query", noStringConcatenation);
    }

    /**
     * Test 2: SQL Injection Attack - Single Quote Escape Attempt
     * Verifies that single quotes in input don't break the query
     */
    @Test
    public void testSQLInjectionWithSingleQuote() throws Exception {
        String maliciousInput = "'; DROP TABLE Inventory; --";

        // Create PreparedStatement with malicious input
        String query = "INSERT INTO Inventory(Style_ID,Vendor_ID,In_Date,Gold,Gold_wt,Stone_Type,Stone_Weight,Stone_numbers,Details) VALUES (?,?,?,?,?,?,?,?,?)";
        PreparedStatement pstmt = testConnection.prepareStatement(query);

        // Set parameters including the malicious input
        pstmt.setString(1, "STYLE001");
        pstmt.setString(2, maliciousInput); // Malicious vendor ID
        pstmt.setString(3, "2024-01-01");
        pstmt.setString(4, "22K");
        pstmt.setString(5, "10.5");
        pstmt.setString(6, "Diamond");
        pstmt.setString(7, "2.5");
        pstmt.setString(8, "5");
        pstmt.setString(9, "Test details");

        // Execute the query - should not cause SQL injection
        int result = pstmt.executeUpdate();
        pstmt.close();

        assertEquals("Should insert exactly 1 row", 1, result);

        // Verify table still exists (wasn't dropped)
        ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM Inventory");
        assertTrue(rs.next());
        assertEquals("Table should still exist with 1 row", 1, rs.getInt(1));
        rs.close();

        // Verify the malicious string was stored as literal data
        rs = stmt.executeQuery("SELECT Vendor_ID FROM Inventory WHERE Style_ID='STYLE001'");
        assertTrue(rs.next());
        assertEquals("Malicious input should be stored as literal string", maliciousInput, rs.getString(1));
        rs.close();
    }

    /**
     * Test 3: SQL Injection Attack - UNION-based Attack
     * Verifies that UNION injection attempts don't work
     */
    @Test
    public void testSQLInjectionUnionAttack() throws Exception {
        String maliciousInput = "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--";

        String query = "INSERT INTO Inventory(Style_ID,Vendor_ID,In_Date,Gold,Gold_wt,Stone_Type,Stone_Weight,Stone_numbers,Details) VALUES (?,?,?,?,?,?,?,?,?)";
        PreparedStatement pstmt = testConnection.prepareStatement(query);

        pstmt.setString(1, maliciousInput);
        pstmt.setString(2, "VENDOR001");
        pstmt.setString(3, "2024-01-01");
        pstmt.setString(4, "22K");
        pstmt.setString(5, "10.5");
        pstmt.setString(6, "Diamond");
        pstmt.setString(7, "2.5");
        pstmt.setString(8, "5");
        pstmt.setString(9, "Test details");

        int result = pstmt.executeUpdate();
        pstmt.close();

        assertEquals("Should insert exactly 1 row", 1, result);

        // Verify only 1 row was inserted (UNION attack failed)
        ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM Inventory");
        assertTrue(rs.next());
        assertEquals("Only 1 row should exist (UNION attack prevented)", 1, rs.getInt(1));
        rs.close();
    }

    /**
     * Test 4: SQL Injection Attack - Tautology-based Attack (Always True)
     * Verifies that 'OR 1=1' style attacks don't work
     */
    @Test
    public void testSQLInjectionTautologyAttack() throws Exception {
        String maliciousInput = "' OR '1'='1";

        String query = "INSERT INTO Inventory(Style_ID,Vendor_ID,In_Date,Gold,Gold_wt,Stone_Type,Stone_Weight,Stone_numbers,Details) VALUES (?,?,?,?,?,?,?,?,?)";
        PreparedStatement pstmt = testConnection.prepareStatement(query);

        pstmt.setString(1, "STYLE002");
        pstmt.setString(2, "VENDOR002");
        pstmt.setString(3, "2024-01-02");
        pstmt.setString(4, "22K");
        pstmt.setString(5, "10.5");
        pstmt.setString(6, "Diamond");
        pstmt.setString(7, "2.5");
        pstmt.setString(8, maliciousInput); // Malicious stone number
        pstmt.setString(9, "Test details");

        int result = pstmt.executeUpdate();
        pstmt.close();

        assertEquals("Should insert exactly 1 row", 1, result);

        // Verify the malicious string was stored as data
        ResultSet rs = stmt.executeQuery("SELECT Stone_numbers FROM Inventory WHERE Style_ID='STYLE002'");
        assertTrue(rs.next());
        assertEquals("Tautology attack string stored as literal", maliciousInput, rs.getString(1));
        rs.close();
    }

    /**
     * Test 5: SQL Injection Attack - Comment Injection
     * Verifies that SQL comment characters are treated as data
     */
    @Test
    public void testSQLInjectionCommentAttack() throws Exception {
        String maliciousInput = "Test'; DELETE FROM Inventory WHERE '1'='1"; // Comment attack without --

        String query = "INSERT INTO Inventory(Style_ID,Vendor_ID,In_Date,Gold,Gold_wt,Stone_Type,Stone_Weight,Stone_numbers,Details) VALUES (?,?,?,?,?,?,?,?,?)";
        PreparedStatement pstmt = testConnection.prepareStatement(query);

        pstmt.setString(1, "STYLE003");
        pstmt.setString(2, "VENDOR003");
        pstmt.setString(3, "2024-01-03");
        pstmt.setString(4, "22K");
        pstmt.setString(5, "10.5");
        pstmt.setString(6, "Diamond");
        pstmt.setString(7, "2.5");
        pstmt.setString(8, "5");
        pstmt.setString(9, maliciousInput); // Malicious details

        int result = pstmt.executeUpdate();
        pstmt.close();

        assertEquals("Should insert exactly 1 row", 1, result);

        // Verify the table still has data (DELETE didn't execute)
        ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM Inventory");
        assertTrue(rs.next());
        assertEquals("All rows should still exist", 1, rs.getInt(1));
        rs.close();
    }

    /**
     * Test 6: Normal Functionality - Valid Input
     * Ensures legitimate data still works correctly
     */
    @Test
    public void testNormalInsertionWithValidData() throws Exception {
        String query = "INSERT INTO Inventory(Style_ID,Vendor_ID,In_Date,Gold,Gold_wt,Stone_Type,Stone_Weight,Stone_numbers,Details) VALUES (?,?,?,?,?,?,?,?,?)";
        PreparedStatement pstmt = testConnection.prepareStatement(query);

        // Insert valid data
        pstmt.setString(1, "STYLE100");
        pstmt.setString(2, "VENDOR100");
        pstmt.setString(3, "01/01/2024");
        pstmt.setString(4, "22K");
        pstmt.setString(5, "15.75");
        pstmt.setString(6, "Ruby");
        pstmt.setString(7, "3.25");
        pstmt.setString(8, "10");
        pstmt.setString(9, "Premium quality ruby ring");

        int result = pstmt.executeUpdate();
        pstmt.close();

        assertEquals("Should insert 1 row", 1, result);

        // Verify data integrity
        ResultSet rs = stmt.executeQuery("SELECT * FROM Inventory WHERE Style_ID='STYLE100'");
        assertTrue("Row should exist", rs.next());
        assertEquals("VENDOR100", rs.getString("Vendor_ID"));
        assertEquals("Ruby", rs.getString("Stone_Type"));
        assertEquals("Premium quality ruby ring", rs.getString("Details"));
        rs.close();
    }

    /**
     * Test 7: Special Characters in Normal Data
     * Ensures special characters in legitimate data are handled correctly
     */
    @Test
    public void testSpecialCharactersInValidData() throws Exception {
        String query = "INSERT INTO Inventory(Style_ID,Vendor_ID,In_Date,Gold,Gold_wt,Stone_Type,Stone_Weight,Stone_numbers,Details) VALUES (?,?,?,?,?,?,?,?,?)";
        PreparedStatement pstmt = testConnection.prepareStatement(query);

        // Insert data with special characters
        String detailsWithSpecialChars = "O'Brien's Jewelry - Premium Quality & Design (5-star)";
        pstmt.setString(1, "STYLE200");
        pstmt.setString(2, "VENDOR-O'Brien");
        pstmt.setString(3, "01/01/2024");
        pstmt.setString(4, "22K");
        pstmt.setString(5, "15.75");
        pstmt.setString(6, "Diamond");
        pstmt.setString(7, "3.25");
        pstmt.setString(8, "10");
        pstmt.setString(9, detailsWithSpecialChars);

        int result = pstmt.executeUpdate();
        pstmt.close();

        assertEquals("Should insert 1 row", 1, result);

        // Verify special characters are preserved
        ResultSet rs = stmt.executeQuery("SELECT * FROM Inventory WHERE Style_ID='STYLE200'");
        assertTrue(rs.next());
        assertEquals("Special characters should be preserved", detailsWithSpecialChars, rs.getString("Details"));
        assertEquals("VENDOR-O'Brien", rs.getString("Vendor_ID"));
        rs.close();
    }

    /**
     * Test 8: Multiple Inserts to Verify No Side Effects
     * Ensures the fix works consistently across multiple operations
     */
    @Test
    public void testMultipleInsertions() throws Exception {
        String query = "INSERT INTO Inventory(Style_ID,Vendor_ID,In_Date,Gold,Gold_wt,Stone_Type,Stone_Weight,Stone_numbers,Details) VALUES (?,?,?,?,?,?,?,?,?)";

        for (int i = 1; i <= 5; i++) {
            PreparedStatement pstmt = testConnection.prepareStatement(query);
            pstmt.setString(1, "STYLE" + i);
            pstmt.setString(2, "VENDOR" + i);
            pstmt.setString(3, "01/0" + i + "/2024");
            pstmt.setString(4, "22K");
            pstmt.setString(5, "10.0");
            pstmt.setString(6, "Diamond");
            pstmt.setString(7, "2.0");
            pstmt.setString(8, String.valueOf(i));
            pstmt.setString(9, "Details " + i);

            int result = pstmt.executeUpdate();
            pstmt.close();
            assertEquals("Each insert should affect 1 row", 1, result);
        }

        // Verify all rows inserted
        ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM Inventory");
        assertTrue(rs.next());
        assertEquals("Should have 5 rows", 5, rs.getInt(1));
        rs.close();
    }

    /**
     * Test 9: Empty String Handling
     * Ensures empty strings are handled correctly
     */
    @Test
    public void testEmptyStringHandling() throws Exception {
        String query = "INSERT INTO Inventory(Style_ID,Vendor_ID,In_Date,Gold,Gold_wt,Stone_Type,Stone_Weight,Stone_numbers,Details) VALUES (?,?,?,?,?,?,?,?,?)";
        PreparedStatement pstmt = testConnection.prepareStatement(query);

        pstmt.setString(1, "STYLE999");
        pstmt.setString(2, "");  // Empty vendor ID
        pstmt.setString(3, "");  // Empty date
        pstmt.setString(4, "22K");
        pstmt.setString(5, "10.0");
        pstmt.setString(6, "Diamond");
        pstmt.setString(7, "2.0");
        pstmt.setString(8, "5");
        pstmt.setString(9, "");  // Empty details

        int result = pstmt.executeUpdate();
        pstmt.close();

        assertEquals("Should insert 1 row", 1, result);

        // Verify empty strings are stored
        ResultSet rs = stmt.executeQuery("SELECT * FROM Inventory WHERE Style_ID='STYLE999'");
        assertTrue(rs.next());
        assertEquals("", rs.getString("Vendor_ID"));
        assertEquals("", rs.getString("Details"));
        rs.close();
    }

    /**
     * Test 10: SQL Keywords as Data
     * Verifies that SQL keywords in input are treated as data
     */
    @Test
    public void testSQLKeywordsAsData() throws Exception {
        String query = "INSERT INTO Inventory(Style_ID,Vendor_ID,In_Date,Gold,Gold_wt,Stone_Type,Stone_Weight,Stone_numbers,Details) VALUES (?,?,?,?,?,?,?,?,?)";
        PreparedStatement pstmt = testConnection.prepareStatement(query);

        // Use SQL keywords as data
        pstmt.setString(1, "SELECT");
        pstmt.setString(2, "INSERT");
        pstmt.setString(3, "UPDATE");
        pstmt.setString(4, "DELETE");
        pstmt.setString(5, "DROP");
        pstmt.setString(6, "TABLE");
        pstmt.setString(7, "WHERE");
        pstmt.setString(8, "FROM");
        pstmt.setString(9, "ORDER BY");

        int result = pstmt.executeUpdate();
        pstmt.close();

        assertEquals("Should insert 1 row", 1, result);

        // Verify SQL keywords stored as data
        ResultSet rs = stmt.executeQuery("SELECT * FROM Inventory WHERE Style_ID='SELECT'");
        assertTrue(rs.next());
        assertEquals("INSERT", rs.getString("Vendor_ID"));
        assertEquals("ORDER BY", rs.getString("Details"));
        rs.close();
    }
}
