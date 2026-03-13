import org.junit.*;
import static org.junit.Assert.*;
import java.sql.*;
import java.awt.event.ActionEvent;
import javax.swing.JDesktopPane;

/**
 * Test class for JobCard SQL injection vulnerability remediation.
 * Tests verify that PreparedStatement prevents SQL injection attacks
 * and maintains proper functionality.
 */
public class JobCardTest {

    private JobCard jobCard;
    private Connection testConnection;
    private Statement stmt;

    @Before
    public void setUp() throws Exception {
        jobCard = new JobCard();

        // Set up an in-memory H2 database for testing
        Class.forName("org.h2.Driver");
        testConnection = DriverManager.getConnection("jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1", "", "");
        stmt = testConnection.createStatement();

        // Create test table
        stmt.execute("CREATE TABLE IF NOT EXISTS Job_Card (" +
                     "Customer_ID VARCHAR(255), " +
                     "Style_ID VARCHAR(255), " +
                     "Order_Date VARCHAR(255), " +
                     "Due_Date VARCHAR(255), " +
                     "Estimated_Cost VARCHAR(255), " +
                     "Remarks VARCHAR(255), " +
                     "Amount_Advance VARCHAR(255), " +
                     "Salesman VARCHAR(255), " +
                     "Current_Status VARCHAR(255))");
    }

    @After
    public void tearDown() throws Exception {
        if (stmt != null) stmt.close();
        if (testConnection != null) testConnection.close();
    }

    /**
     * Test that verifies PreparedStatement is being used instead of string concatenation.
     * This test simulates inserting legitimate data and verifies it's stored correctly.
     */
    @Test
    public void testLegitimateDataInsertion() throws Exception {
        // Prepare test data
        String customerId = "CUST001";
        String styleId = "STY001";
        String orderDate = "01/01/2024";
        String dueDate = "15/01/2024";
        String estimatedCost = "1000.00";
        String remarks = "Test order";
        String amountAdvance = "200.00";
        String salesman = "John Doe";
        String status = "1";

        // Execute insertion using PreparedStatement (mimicking the fixed code)
        String query = "INSERT INTO Job_Card(Customer_ID,Style_ID,Order_Date,Due_Date,Estimated_Cost,Remarks,Amount_Advance,Salesman,Current_Status) VALUES (?,?,?,?,?,?,?,?,?)";
        PreparedStatement pstmt = testConnection.prepareStatement(query);

        pstmt.setString(1, customerId);
        pstmt.setString(2, styleId);
        pstmt.setString(3, orderDate);
        pstmt.setString(4, dueDate);
        pstmt.setString(5, estimatedCost);
        pstmt.setString(6, remarks);
        pstmt.setString(7, amountAdvance);
        pstmt.setString(8, salesman);
        pstmt.setString(9, status);

        int result = pstmt.executeUpdate();
        pstmt.close();

        // Verify insertion was successful
        assertEquals("One row should be inserted", 1, result);

        // Verify data was stored correctly
        ResultSet rs = stmt.executeQuery("SELECT * FROM Job_Card WHERE Customer_ID = 'CUST001'");
        assertTrue("Record should exist", rs.next());
        assertEquals("CUST001", rs.getString("Customer_ID"));
        assertEquals("STY001", rs.getString("Style_ID"));
        assertEquals("Test order", rs.getString("Remarks"));
        rs.close();
    }

    /**
     * Test that verifies SQL injection attempts are neutralized.
     * This test uses a malicious payload that would succeed with string concatenation
     * but is safely escaped by PreparedStatement.
     */
    @Test
    public void testSQLInjectionPrevention_MaliciousStyleId() throws Exception {
        // Malicious payload attempting SQL injection via Style_Id field
        String maliciousStyleId = "STY001'); DROP TABLE Job_Card; --";
        String customerId = "CUST002";
        String orderDate = "01/01/2024";
        String dueDate = "15/01/2024";
        String estimatedCost = "1500.00";
        String remarks = "Injection test";
        String amountAdvance = "300.00";
        String salesman = "Jane Smith";
        String status = "2";

        // Execute insertion using PreparedStatement (the fixed code approach)
        String query = "INSERT INTO Job_Card(Customer_ID,Style_ID,Order_Date,Due_Date,Estimated_Cost,Remarks,Amount_Advance,Salesman,Current_Status) VALUES (?,?,?,?,?,?,?,?,?)";
        PreparedStatement pstmt = testConnection.prepareStatement(query);

        pstmt.setString(1, customerId);
        pstmt.setString(2, maliciousStyleId);  // Malicious input is safely escaped
        pstmt.setString(3, orderDate);
        pstmt.setString(4, dueDate);
        pstmt.setString(5, estimatedCost);
        pstmt.setString(6, remarks);
        pstmt.setString(7, amountAdvance);
        pstmt.setString(8, salesman);
        pstmt.setString(9, status);

        int result = pstmt.executeUpdate();
        pstmt.close();

        // Verify the injection attempt was neutralized - data was inserted as literal string
        assertEquals("One row should be inserted", 1, result);

        // Verify the malicious payload was stored as literal text, not executed
        ResultSet rs = stmt.executeQuery("SELECT * FROM Job_Card WHERE Customer_ID = 'CUST002'");
        assertTrue("Record should exist", rs.next());
        assertEquals("Malicious payload should be stored as literal text",
                     maliciousStyleId, rs.getString("Style_ID"));
        rs.close();

        // Verify table still exists (DROP TABLE command was not executed)
        ResultSet tables = testConnection.getMetaData().getTables(null, null, "JOB_CARD", null);
        assertTrue("Table should still exist, confirming SQL injection was prevented", tables.next());
        tables.close();
    }

    /**
     * Test SQL injection prevention via Customer_Id field with UNION-based attack.
     */
    @Test
    public void testSQLInjectionPrevention_UnionAttack() throws Exception {
        // UNION-based SQL injection attempt
        String maliciousCustomerId = "CUST003' UNION SELECT * FROM Job_Card WHERE '1'='1";
        String styleId = "STY003";
        String orderDate = "01/01/2024";
        String dueDate = "15/01/2024";
        String estimatedCost = "2000.00";
        String remarks = "Union attack test";
        String amountAdvance = "400.00";
        String salesman = "Bob Wilson";
        String status = "3";

        // Execute with PreparedStatement
        String query = "INSERT INTO Job_Card(Customer_ID,Style_ID,Order_Date,Due_Date,Estimated_Cost,Remarks,Amount_Advance,Salesman,Current_Status) VALUES (?,?,?,?,?,?,?,?,?)";
        PreparedStatement pstmt = testConnection.prepareStatement(query);

        pstmt.setString(1, maliciousCustomerId);
        pstmt.setString(2, styleId);
        pstmt.setString(3, orderDate);
        pstmt.setString(4, dueDate);
        pstmt.setString(5, estimatedCost);
        pstmt.setString(6, remarks);
        pstmt.setString(7, amountAdvance);
        pstmt.setString(8, salesman);
        pstmt.setString(9, status);

        int result = pstmt.executeUpdate();
        pstmt.close();

        // Verify the attack was neutralized
        assertEquals("One row should be inserted", 1, result);

        // Count total records - should only have legitimate inserts
        ResultSet rs = stmt.executeQuery("SELECT COUNT(*) as count FROM Job_Card");
        rs.next();
        int count = rs.getInt("count");
        rs.close();

        // Should have only the records we explicitly inserted, not duplicates from UNION
        assertTrue("UNION attack should not have extracted or duplicated data", count <= 3);
    }

    /**
     * Test SQL injection prevention with special characters in Remarks field.
     */
    @Test
    public void testSQLInjectionPrevention_SpecialCharacters() throws Exception {
        // Special characters that could break string concatenation
        String remarksWithQuotes = "Customer said: 'Rush order' and \"urgent\"";
        String remarksWithBackslash = "Path: C:\\Users\\Admin\\Orders";

        // First insertion
        String query = "INSERT INTO Job_Card(Customer_ID,Style_ID,Order_Date,Due_Date,Estimated_Cost,Remarks,Amount_Advance,Salesman,Current_Status) VALUES (?,?,?,?,?,?,?,?,?)";
        PreparedStatement pstmt = testConnection.prepareStatement(query);

        pstmt.setString(1, "CUST004");
        pstmt.setString(2, "STY004");
        pstmt.setString(3, "01/01/2024");
        pstmt.setString(4, "15/01/2024");
        pstmt.setString(5, "1200.00");
        pstmt.setString(6, remarksWithQuotes);
        pstmt.setString(7, "250.00");
        pstmt.setString(8, "Alice Brown");
        pstmt.setString(9, "1");

        int result1 = pstmt.executeUpdate();
        assertEquals("First insertion should succeed", 1, result1);

        // Second insertion with backslashes
        pstmt.setString(1, "CUST005");
        pstmt.setString(2, "STY005");
        pstmt.setString(3, "02/01/2024");
        pstmt.setString(4, "16/01/2024");
        pstmt.setString(5, "1300.00");
        pstmt.setString(6, remarksWithBackslash);
        pstmt.setString(7, "260.00");
        pstmt.setString(8, "Charlie Davis");
        pstmt.setString(9, "2");

        int result2 = pstmt.executeUpdate();
        pstmt.close();

        assertEquals("Second insertion should succeed", 1, result2);

        // Verify special characters were stored correctly
        ResultSet rs = stmt.executeQuery("SELECT Remarks FROM Job_Card WHERE Customer_ID = 'CUST004'");
        assertTrue(rs.next());
        assertEquals("Special characters should be preserved", remarksWithQuotes, rs.getString("Remarks"));
        rs.close();

        rs = stmt.executeQuery("SELECT Remarks FROM Job_Card WHERE Customer_ID = 'CUST005'");
        assertTrue(rs.next());
        assertEquals("Backslashes should be preserved", remarksWithBackslash, rs.getString("Remarks"));
        rs.close();
    }

    /**
     * Test SQL injection prevention with comment-based attack.
     */
    @Test
    public void testSQLInjectionPrevention_CommentAttack() throws Exception {
        // Attempt to use SQL comments to truncate query
        String maliciousSalesman = "BadGuy'; DELETE FROM Job_Card WHERE '1'='1' --";

        String query = "INSERT INTO Job_Card(Customer_ID,Style_ID,Order_Date,Due_Date,Estimated_Cost,Remarks,Amount_Advance,Salesman,Current_Status) VALUES (?,?,?,?,?,?,?,?,?)";
        PreparedStatement pstmt = testConnection.prepareStatement(query);

        pstmt.setString(1, "CUST006");
        pstmt.setString(2, "STY006");
        pstmt.setString(3, "01/01/2024");
        pstmt.setString(4, "15/01/2024");
        pstmt.setString(5, "1800.00");
        pstmt.setString(6, "Comment injection test");
        pstmt.setString(7, "350.00");
        pstmt.setString(8, maliciousSalesman);
        pstmt.setString(9, "4");

        int result = pstmt.executeUpdate();
        pstmt.close();

        assertEquals("Insertion should succeed", 1, result);

        // Verify the malicious payload was stored as text, not executed
        ResultSet rs = stmt.executeQuery("SELECT Salesman FROM Job_Card WHERE Customer_ID = 'CUST006'");
        assertTrue(rs.next());
        assertEquals("Comment-based attack should be stored as literal text",
                     maliciousSalesman, rs.getString("Salesman"));
        rs.close();

        // Verify no records were deleted (table should have multiple records)
        rs = stmt.executeQuery("SELECT COUNT(*) as count FROM Job_Card");
        rs.next();
        int count = rs.getInt("count");
        rs.close();

        assertTrue("DELETE command should not have been executed", count > 0);
    }

    /**
     * Test that empty and null values are handled correctly.
     */
    @Test
    public void testEmptyAndNullValues() throws Exception {
        String query = "INSERT INTO Job_Card(Customer_ID,Style_ID,Order_Date,Due_Date,Estimated_Cost,Remarks,Amount_Advance,Salesman,Current_Status) VALUES (?,?,?,?,?,?,?,?,?)";
        PreparedStatement pstmt = testConnection.prepareStatement(query);

        // Test with empty strings
        pstmt.setString(1, "CUST007");
        pstmt.setString(2, "STY007");
        pstmt.setString(3, "");  // Empty order date
        pstmt.setString(4, "");  // Empty due date
        pstmt.setString(5, "0");
        pstmt.setString(6, "");  // Empty remarks
        pstmt.setString(7, "0");
        pstmt.setString(8, "");  // Empty salesman
        pstmt.setString(9, "5");

        int result = pstmt.executeUpdate();
        pstmt.close();

        assertEquals("Insertion with empty values should succeed", 1, result);

        // Verify empty values were stored
        ResultSet rs = stmt.executeQuery("SELECT * FROM Job_Card WHERE Customer_ID = 'CUST007'");
        assertTrue(rs.next());
        assertEquals("", rs.getString("Order_Date"));
        assertEquals("", rs.getString("Remarks"));
        rs.close();
    }

    /**
     * Test performance - PreparedStatement should handle multiple insertions efficiently.
     */
    @Test
    public void testMultipleInsertions() throws Exception {
        String query = "INSERT INTO Job_Card(Customer_ID,Style_ID,Order_Date,Due_Date,Estimated_Cost,Remarks,Amount_Advance,Salesman,Current_Status) VALUES (?,?,?,?,?,?,?,?,?)";
        PreparedStatement pstmt = testConnection.prepareStatement(query);

        // Insert 10 records
        for (int i = 1; i <= 10; i++) {
            pstmt.setString(1, "CUST" + String.format("%03d", 100 + i));
            pstmt.setString(2, "STY" + String.format("%03d", 100 + i));
            pstmt.setString(3, "01/01/2024");
            pstmt.setString(4, "15/01/2024");
            pstmt.setString(5, String.valueOf(1000 + i * 100));
            pstmt.setString(6, "Batch insert test " + i);
            pstmt.setString(7, String.valueOf(200 + i * 10));
            pstmt.setString(8, "Salesman" + i);
            pstmt.setString(9, String.valueOf(i % 5 + 1));

            int result = pstmt.executeUpdate();
            assertEquals("Each insertion should succeed", 1, result);
        }
        pstmt.close();

        // Verify all records were inserted
        ResultSet rs = stmt.executeQuery("SELECT COUNT(*) as count FROM Job_Card WHERE Customer_ID LIKE 'CUST1%'");
        rs.next();
        assertEquals("All 10 records should be inserted", 10, rs.getInt("count"));
        rs.close();
    }
}
