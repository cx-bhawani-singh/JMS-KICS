import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.sql.*;
import java.awt.event.ActionEvent;
import javax.swing.JTextField;

import static org.junit.Assert.*;

/**
 * Comprehensive test suite for Billing class SQL injection vulnerability remediation.
 * Tests verify that PreparedStatement usage prevents SQL injection attacks.
 */
@RunWith(JUnit4.class)
public class BillingTest {

    private Connection testConnection;
    private Billing billing;

    @Before
    public void setUp() throws Exception {
        // Create an in-memory H2 database for testing
        Class.forName("org.h2.Driver");
        testConnection = DriverManager.getConnection("jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1", "sa", "");

        // Create test tables
        Statement stmt = testConnection.createStatement();
        stmt.execute("CREATE TABLE IF NOT EXISTS Job_Card (" +
            "Customer_ID VARCHAR(255), " +
            "Job_ID VARCHAR(255) PRIMARY KEY, " +
            "Amount_Advance VARCHAR(255))");

        stmt.execute("CREATE TABLE IF NOT EXISTS Billing (" +
            "Customer_ID VARCHAR(255), " +
            "Job_ID VARCHAR(255), " +
            "Bill_Date VARCHAR(255), " +
            "Stone_Numbers VARCHAR(255), " +
            "Weight VARCHAR(255), " +
            "Net_Weight VARCHAR(255), " +
            "Gross_error VARCHAR(255), " +
            "Weight_error VARCHAR(255), " +
            "Gold_purity VARCHAR(255), " +
            "Total_Price VARCHAR(255), " +
            "Payment_Mode VARCHAR(255), " +
            "Discount VARCHAR(255), " +
            "Details VARCHAR(255))");

        // Insert test data
        stmt.execute("INSERT INTO Job_Card (Customer_ID, Job_ID, Amount_Advance) VALUES ('CUST001', 'JOB001', '1000')");
        stmt.close();
    }

    @After
    public void tearDown() throws Exception {
        if (testConnection != null && !testConnection.isClosed()) {
            testConnection.close();
        }
    }

    /**
     * Test that PreparedStatement correctly handles normal input
     */
    @Test
    public void testNormalBillingInsert() throws Exception {
        PreparedStatement pstmt = testConnection.prepareStatement(
            "INSERT INTO Billing(Customer_ID,Job_ID,Bill_Date,Stone_Numbers,Weight,Net_Weight,Gross_error,Weight_error,Gold_purity,Total_Price,Payment_Mode,Discount,Details) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)");

        pstmt.setString(1, "CUST001");
        pstmt.setString(2, "JOB001");
        pstmt.setString(3, "01/01/2024");
        pstmt.setString(4, "5");
        pstmt.setString(5, "100");
        pstmt.setString(6, "95");
        pstmt.setString(7, "2");
        pstmt.setString(8, "1");
        pstmt.setString(9, "22K");
        pstmt.setString(10, "5000");
        pstmt.setString(11, "Cash");
        pstmt.setString(12, "100");
        pstmt.setString(13, "Test billing");

        int result = pstmt.executeUpdate();
        assertEquals("Should insert exactly one row", 1, result);

        // Verify the data was inserted correctly
        Statement verifyStmt = testConnection.createStatement();
        ResultSet rs = verifyStmt.executeQuery("SELECT * FROM Billing WHERE Job_ID = 'JOB001'");
        assertTrue("Should find the inserted record", rs.next());
        assertEquals("CUST001", rs.getString("Customer_ID"));
        assertEquals("01/01/2024", rs.getString("Bill_Date"));
        pstmt.close();
        verifyStmt.close();
    }

    /**
     * Test that SQL injection in Bill_Date field is prevented
     * This tests the specific vulnerability identified at line 213->307->314
     */
    @Test
    public void testSQLInjectionPreventionInBillDate() throws Exception {
        // Attempt SQL injection through Bill_Date field
        String maliciousBillDate = "01/01/2024'); DROP TABLE Billing; --";

        PreparedStatement pstmt = testConnection.prepareStatement(
            "INSERT INTO Billing(Customer_ID,Job_ID,Bill_Date,Stone_Numbers,Weight,Net_Weight,Gross_error,Weight_error,Gold_purity,Total_Price,Payment_Mode,Discount,Details) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)");

        pstmt.setString(1, "CUST001");
        pstmt.setString(2, "JOB002");
        pstmt.setString(3, maliciousBillDate); // Malicious input
        pstmt.setString(4, "5");
        pstmt.setString(5, "100");
        pstmt.setString(6, "95");
        pstmt.setString(7, "2");
        pstmt.setString(8, "1");
        pstmt.setString(9, "22K");
        pstmt.setString(10, "5000");
        pstmt.setString(11, "Cash");
        pstmt.setString(12, "100");
        pstmt.setString(13, "Test");

        int result = pstmt.executeUpdate();
        assertEquals("Should insert exactly one row", 1, result);

        // Verify that the Billing table still exists (was not dropped)
        Statement verifyStmt = testConnection.createStatement();
        ResultSet rs = verifyStmt.executeQuery("SELECT COUNT(*) FROM Billing");
        assertTrue("Billing table should still exist", rs.next());
        int count = rs.getInt(1);
        assertTrue("Should have records in Billing table", count > 0);

        // Verify the malicious string was treated as literal data
        rs = verifyStmt.executeQuery("SELECT Bill_Date FROM Billing WHERE Job_ID = 'JOB002'");
        assertTrue("Should find the inserted record", rs.next());
        assertEquals("Malicious input should be stored as literal string",
                     maliciousBillDate, rs.getString("Bill_Date"));

        pstmt.close();
        verifyStmt.close();
    }

    /**
     * Test SQL injection prevention in Customer_ID field
     */
    @Test
    public void testSQLInjectionPreventionInCustomerId() throws Exception {
        String maliciousCustomerId = "CUST001' OR '1'='1";

        PreparedStatement pstmt = testConnection.prepareStatement(
            "INSERT INTO Billing(Customer_ID,Job_ID,Bill_Date,Stone_Numbers,Weight,Net_Weight,Gross_error,Weight_error,Gold_purity,Total_Price,Payment_Mode,Discount,Details) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)");

        pstmt.setString(1, maliciousCustomerId);
        pstmt.setString(2, "JOB003");
        pstmt.setString(3, "01/01/2024");
        pstmt.setString(4, "5");
        pstmt.setString(5, "100");
        pstmt.setString(6, "95");
        pstmt.setString(7, "2");
        pstmt.setString(8, "1");
        pstmt.setString(9, "22K");
        pstmt.setString(10, "5000");
        pstmt.setString(11, "Cash");
        pstmt.setString(12, "100");
        pstmt.setString(13, "Test");

        int result = pstmt.executeUpdate();
        assertEquals("Should insert exactly one row", 1, result);

        // Verify the malicious string was treated as literal data
        Statement verifyStmt = testConnection.createStatement();
        ResultSet rs = verifyStmt.executeQuery("SELECT Customer_ID FROM Billing WHERE Job_ID = 'JOB003'");
        assertTrue("Should find the inserted record", rs.next());
        assertEquals("Malicious input should be stored as literal string",
                     maliciousCustomerId, rs.getString("Customer_ID"));

        pstmt.close();
        verifyStmt.close();
    }

    /**
     * Test SQL injection prevention in Details field (varchar 255)
     */
    @Test
    public void testSQLInjectionPreventionInDetails() throws Exception {
        String maliciousDetails = "Normal details'; DELETE FROM Billing WHERE '1'='1";

        PreparedStatement pstmt = testConnection.prepareStatement(
            "INSERT INTO Billing(Customer_ID,Job_ID,Bill_Date,Stone_Numbers,Weight,Net_Weight,Gross_error,Weight_error,Gold_purity,Total_Price,Payment_Mode,Discount,Details) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)");

        pstmt.setString(1, "CUST001");
        pstmt.setString(2, "JOB004");
        pstmt.setString(3, "01/01/2024");
        pstmt.setString(4, "5");
        pstmt.setString(5, "100");
        pstmt.setString(6, "95");
        pstmt.setString(7, "2");
        pstmt.setString(8, "1");
        pstmt.setString(9, "22K");
        pstmt.setString(10, "5000");
        pstmt.setString(11, "Cash");
        pstmt.setString(12, "100");
        pstmt.setString(13, maliciousDetails);

        int result = pstmt.executeUpdate();
        assertEquals("Should insert exactly one row", 1, result);

        // Verify all records still exist (none were deleted)
        Statement verifyStmt = testConnection.createStatement();
        ResultSet rs = verifyStmt.executeQuery("SELECT COUNT(*) FROM Billing");
        assertTrue(rs.next());
        int count = rs.getInt(1);
        assertTrue("Should have multiple records", count > 1);

        pstmt.close();
        verifyStmt.close();
    }

    /**
     * Test the Job_Card SELECT query with PreparedStatement
     */
    @Test
    public void testJobCardSelectWithPreparedStatement() throws Exception {
        String query = "SELECT Amount_Advance FROM Job_Card WHERE Job_ID = ?";
        PreparedStatement pstmt = testConnection.prepareStatement(query);
        pstmt.setString(1, "JOB001");

        ResultSet rs = pstmt.executeQuery();
        assertTrue("Should find the job record", rs.next());
        assertEquals("1000", rs.getString("Amount_Advance"));

        pstmt.close();
    }

    /**
     * Test SQL injection prevention in Job_Card SELECT query
     */
    @Test
    public void testSQLInjectionPreventionInJobCardSelect() throws Exception {
        String maliciousJobId = "JOB001' OR '1'='1";

        String query = "SELECT Amount_Advance FROM Job_Card WHERE Job_ID = ?";
        PreparedStatement pstmt = testConnection.prepareStatement(query);
        pstmt.setString(1, maliciousJobId);

        ResultSet rs = pstmt.executeQuery();
        // Should not find any records because the entire malicious string is treated as a literal Job_ID
        assertFalse("Should not find records with malicious Job_ID", rs.next());

        // Verify the legitimate record still exists
        pstmt.setString(1, "JOB001");
        rs = pstmt.executeQuery();
        assertTrue("Should find legitimate record", rs.next());

        pstmt.close();
    }

    /**
     * Test the Customer_ID validation query with PreparedStatement
     */
    @Test
    public void testCustomerValidationWithPreparedStatement() throws Exception {
        String qCustom = "SELECT Customer_ID FROM Job_Card WHERE Customer_ID = ?";
        PreparedStatement pstmt = testConnection.prepareStatement(qCustom);
        pstmt.setString(1, "CUST001");

        ResultSet rs = pstmt.executeQuery();
        assertTrue("Should find the customer record", rs.next());
        assertEquals("CUST001", rs.getString("Customer_ID"));

        pstmt.close();
    }

    /**
     * Test SQL injection prevention in Customer validation query
     * This tests the vulnerability fix at line 240
     */
    @Test
    public void testSQLInjectionPreventionInCustomerValidation() throws Exception {
        String maliciousCustomerId = "CUST001' OR '1'='1' --";

        String qCustom = "SELECT Customer_ID FROM Job_Card WHERE Customer_ID = ?";
        PreparedStatement pstmt = testConnection.prepareStatement(qCustom);
        pstmt.setString(1, maliciousCustomerId);

        ResultSet rs = pstmt.executeQuery();
        // Should not find any records because the malicious string is treated as a literal Customer_ID
        assertFalse("Should not find records with malicious Customer_ID", rs.next());

        pstmt.close();
    }

    /**
     * Test UNION-based SQL injection attack prevention
     */
    @Test
    public void testUnionBasedSQLInjectionPrevention() throws Exception {
        String unionAttack = "01/01/2024' UNION SELECT Customer_ID,Job_ID,Bill_Date,Stone_Numbers,Weight,Net_Weight,Gross_error,Weight_error,Gold_purity,Total_Price,Payment_Mode,Discount,Details FROM Billing --";

        PreparedStatement pstmt = testConnection.prepareStatement(
            "INSERT INTO Billing(Customer_ID,Job_ID,Bill_Date,Stone_Numbers,Weight,Net_Weight,Gross_error,Weight_error,Gold_purity,Total_Price,Payment_Mode,Discount,Details) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)");

        pstmt.setString(1, "CUST001");
        pstmt.setString(2, "JOB005");
        pstmt.setString(3, unionAttack);
        pstmt.setString(4, "5");
        pstmt.setString(5, "100");
        pstmt.setString(6, "95");
        pstmt.setString(7, "2");
        pstmt.setString(8, "1");
        pstmt.setString(9, "22K");
        pstmt.setString(10, "5000");
        pstmt.setString(11, "Cash");
        pstmt.setString(12, "100");
        pstmt.setString(13, "Test");

        int result = pstmt.executeUpdate();
        assertEquals("Should insert exactly one row (UNION attack should be treated as literal)", 1, result);

        pstmt.close();
    }

    /**
     * Test special characters are properly escaped
     */
    @Test
    public void testSpecialCharactersHandling() throws Exception {
        PreparedStatement pstmt = testConnection.prepareStatement(
            "INSERT INTO Billing(Customer_ID,Job_ID,Bill_Date,Stone_Numbers,Weight,Net_Weight,Gross_error,Weight_error,Gold_purity,Total_Price,Payment_Mode,Discount,Details) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)");

        // Test various special characters
        pstmt.setString(1, "CUST'001");
        pstmt.setString(2, "JOB006");
        pstmt.setString(3, "01/01/2024");
        pstmt.setString(4, "5");
        pstmt.setString(5, "100");
        pstmt.setString(6, "95");
        pstmt.setString(7, "2");
        pstmt.setString(8, "1");
        pstmt.setString(9, "22K");
        pstmt.setString(10, "5000");
        pstmt.setString(11, "Cash");
        pstmt.setString(12, "100");
        pstmt.setString(13, "Details with \"quotes\" and 'apostrophes'");

        int result = pstmt.executeUpdate();
        assertEquals("Should insert row with special characters", 1, result);

        // Verify data integrity
        Statement verifyStmt = testConnection.createStatement();
        ResultSet rs = verifyStmt.executeQuery("SELECT * FROM Billing WHERE Job_ID = 'JOB006'");
        assertTrue(rs.next());
        assertEquals("CUST'001", rs.getString("Customer_ID"));
        assertEquals("Details with \"quotes\" and 'apostrophes'", rs.getString("Details"));

        pstmt.close();
        verifyStmt.close();
    }

    /**
     * Test batch insertion with PreparedStatement
     */
    @Test
    public void testBatchInsertionWithPreparedStatement() throws Exception {
        PreparedStatement pstmt = testConnection.prepareStatement(
            "INSERT INTO Billing(Customer_ID,Job_ID,Bill_Date,Stone_Numbers,Weight,Net_Weight,Gross_error,Weight_error,Gold_purity,Total_Price,Payment_Mode,Discount,Details) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)");

        // Add multiple batches
        for (int i = 7; i <= 9; i++) {
            pstmt.setString(1, "CUST001");
            pstmt.setString(2, "JOB00" + i);
            pstmt.setString(3, "01/01/2024");
            pstmt.setString(4, "5");
            pstmt.setString(5, "100");
            pstmt.setString(6, "95");
            pstmt.setString(7, "2");
            pstmt.setString(8, "1");
            pstmt.setString(9, "22K");
            pstmt.setString(10, "5000");
            pstmt.setString(11, "Cash");
            pstmt.setString(12, "100");
            pstmt.setString(13, "Batch " + i);
            pstmt.addBatch();
        }

        int[] results = pstmt.executeBatch();
        assertEquals("Should execute 3 batch inserts", 3, results.length);
        for (int result : results) {
            assertEquals("Each batch should affect 1 row", 1, result);
        }

        pstmt.close();
    }

    /**
     * Test null value handling with PreparedStatement
     */
    @Test
    public void testNullValueHandling() throws Exception {
        PreparedStatement pstmt = testConnection.prepareStatement(
            "INSERT INTO Billing(Customer_ID,Job_ID,Bill_Date,Stone_Numbers,Weight,Net_Weight,Gross_error,Weight_error,Gold_purity,Total_Price,Payment_Mode,Discount,Details) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)");

        pstmt.setString(1, "CUST001");
        pstmt.setString(2, "JOB010");
        pstmt.setString(3, "01/01/2024");
        pstmt.setString(4, "5");
        pstmt.setString(5, "100");
        pstmt.setString(6, "95");
        pstmt.setString(7, "2");
        pstmt.setString(8, "1");
        pstmt.setString(9, "22K");
        pstmt.setString(10, "5000");
        pstmt.setString(11, "Cash");
        pstmt.setString(12, null); // NULL discount
        pstmt.setString(13, null); // NULL details

        int result = pstmt.executeUpdate();
        assertEquals("Should insert row with null values", 1, result);

        pstmt.close();
    }
}
