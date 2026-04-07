import org.junit.*;
import static org.junit.Assert.*;
import java.sql.*;
import java.awt.event.ActionEvent;
import javax.swing.*;

/**
 * Comprehensive test suite for Billing class SQL injection remediation.
 *
 * These tests verify that the SQL injection vulnerability has been properly fixed
 * by ensuring that user input containing SQL injection payloads is safely handled
 * through parameterized queries using PreparedStatement.
 */
public class BillingTest {

    private Connection testConnection;
    private Billing billingInstance;

    /**
     * Set up test database connection and Billing instance before each test.
     * Creates an in-memory H2 database for testing.
     */
    @Before
    public void setUp() throws Exception {
        // Use H2 in-memory database for testing
        Class.forName("org.h2.Driver");
        testConnection = DriverManager.getConnection("jdbc:h2:mem:test;DB_CLOSE_DELAY=-1", "sa", "");

        // Create test tables matching the application schema
        Statement stmt = testConnection.createStatement();

        // Create Job_Card table for foreign key validation
        stmt.execute("CREATE TABLE IF NOT EXISTS Job_Card (" +
                    "Job_ID VARCHAR(50) PRIMARY KEY, " +
                    "Customer_ID VARCHAR(50), " +
                    "Amount_Advance DECIMAL(10,2))");

        // Create Billing table
        stmt.execute("CREATE TABLE IF NOT EXISTS Billing (" +
                    "Billing_ID INT AUTO_INCREMENT PRIMARY KEY, " +
                    "Customer_ID VARCHAR(50), " +
                    "Job_ID VARCHAR(50), " +
                    "Bill_Date VARCHAR(50), " +
                    "Stone_Numbers VARCHAR(50), " +
                    "Weight VARCHAR(50), " +
                    "Net_Weight VARCHAR(50), " +
                    "Gross_error VARCHAR(50), " +
                    "Weight_error VARCHAR(50), " +
                    "Gold_purity VARCHAR(50), " +
                    "Total_Price VARCHAR(50), " +
                    "Payment_Mode VARCHAR(50), " +
                    "Discount VARCHAR(50), " +
                    "Details VARCHAR(255))");

        // Insert test data into Job_Card
        stmt.execute("INSERT INTO Job_Card (Job_ID, Customer_ID, Amount_Advance) VALUES ('JOB001', 'CUST001', 1000.00)");
        stmt.execute("INSERT INTO Job_Card (Job_ID, Customer_ID, Amount_Advance) VALUES ('JOB002', 'CUST001', 2000.00)");

        stmt.close();

        // Create Billing instance and inject test connection
        billingInstance = new Billing();
        // Use reflection to set the test connection
        java.lang.reflect.Field conField = Billing.class.getDeclaredField("con");
        conField.setAccessible(true);
        conField.set(billingInstance, testConnection);
    }

    /**
     * Clean up test resources after each test.
     */
    @After
    public void tearDown() throws Exception {
        if (testConnection != null && !testConnection.isClosed()) {
            Statement stmt = testConnection.createStatement();
            stmt.execute("DROP TABLE IF EXISTS Billing");
            stmt.execute("DROP TABLE IF EXISTS Job_Card");
            stmt.close();
            testConnection.close();
        }
    }

    /**
     * Test that normal legitimate data is properly inserted into the database.
     * This ensures the remediation maintains the original functionality.
     */
    @Test
    public void testLegitimateDataInsertion() throws Exception {
        // Prepare legitimate test data
        setTextFieldValues(
            "CUST001",           // Customer_Id
            "JOB001",            // Job_Id
            "01/01/2024",        // Bill_Date
            "5",                 // Stone_Numbers
            "10.5",              // Weight
            "9.8",               // Net_Weight
            "0.2",               // Gross_Err
            "0.1",               // Weight_Err
            "22",                // Gold_Purity
            "50000",             // Total_Price
            "1000"               // Discount
        );
        billingInstance.Details.setText("Test billing details");

        // Trigger the action
        ActionEvent mockEvent = new ActionEvent(billingInstance.submit, ActionEvent.ACTION_PERFORMED, "submit");
        billingInstance.actionPerformed(mockEvent);

        // Verify data was inserted correctly
        Statement stmt = testConnection.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM Billing WHERE Customer_ID = 'CUST001' AND Job_ID = 'JOB001'");

        assertTrue("Record should be inserted", rs.next());
        assertEquals("CUST001", rs.getString("Customer_ID"));
        assertEquals("JOB001", rs.getString("Job_ID"));
        assertEquals("01/01/2024", rs.getString("Bill_Date"));
        assertEquals("5", rs.getString("Stone_Numbers"));
        assertEquals("10.5", rs.getString("Weight"));
        assertEquals("9.8", rs.getString("Net_Weight"));
        assertEquals("0.2", rs.getString("Gross_error"));
        assertEquals("0.1", rs.getString("Weight_error"));
        assertEquals("22", rs.getString("Gold_purity"));
        assertEquals("50000", rs.getString("Total_Price"));
        assertEquals("Cash", rs.getString("Payment_Mode"));
        assertEquals("1000", rs.getString("Discount"));
        assertEquals("Test billing details", rs.getString("Details"));

        rs.close();
        stmt.close();
    }

    /**
     * Test that SQL injection attempts in Stone_Numbers field are safely handled.
     * This is the primary field identified in the vulnerability report.
     */
    @Test
    public void testSQLInjectionInStoneNumbers_BasicPayload() throws Exception {
        // SQL injection payload attempting to manipulate the query
        String sqlInjectionPayload = "5' OR '1'='1";

        setTextFieldValues(
            "CUST001",
            "JOB001",
            "01/01/2024",
            sqlInjectionPayload,  // Malicious input in Stone_Numbers
            "10.5",
            "9.8",
            "0.2",
            "0.1",
            "22",
            "50000",
            "1000"
        );
        billingInstance.Details.setText("Injection test");

        // Execute the action
        ActionEvent mockEvent = new ActionEvent(billingInstance.submit, ActionEvent.ACTION_PERFORMED, "submit");
        billingInstance.actionPerformed(mockEvent);

        // Verify the payload was treated as literal data, not SQL code
        Statement stmt = testConnection.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT Stone_Numbers FROM Billing WHERE Job_ID = 'JOB001'");

        assertTrue("Record should be inserted", rs.next());
        // The injection payload should be stored as literal text, not executed as SQL
        assertEquals("5' OR '1'='1", rs.getString("Stone_Numbers"));

        // Verify only one record was inserted (not bypassed by OR '1'='1')
        int count = 0;
        ResultSet countRs = stmt.executeQuery("SELECT COUNT(*) as total FROM Billing WHERE Job_ID = 'JOB001'");
        if (countRs.next()) {
            count = countRs.getInt("total");
        }
        assertEquals("Only one record should be inserted", 1, count);

        countRs.close();
        rs.close();
        stmt.close();
    }

    /**
     * Test SQL injection payload attempting to drop tables.
     */
    @Test
    public void testSQLInjectionInStoneNumbers_DropTableAttempt() throws Exception {
        String sqlInjectionPayload = "5'; DROP TABLE Billing; --";

        setTextFieldValues(
            "CUST001",
            "JOB002",
            "02/01/2024",
            sqlInjectionPayload,  // Malicious input attempting to drop table
            "12.0",
            "11.5",
            "0.3",
            "0.15",
            "24",
            "75000",
            "2000"
        );
        billingInstance.Details.setText("Drop table test");

        // Execute the action
        ActionEvent mockEvent = new ActionEvent(billingInstance.submit, ActionEvent.ACTION_PERFORMED, "submit");
        billingInstance.actionPerformed(mockEvent);

        // Verify the table still exists and the payload was stored as literal data
        Statement stmt = testConnection.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT Stone_Numbers FROM Billing WHERE Job_ID = 'JOB002'");

        assertTrue("Record should be inserted and table should still exist", rs.next());
        assertEquals("5'; DROP TABLE Billing; --", rs.getString("Stone_Numbers"));

        // Verify Billing table still exists by checking its structure
        ResultSet tables = testConnection.getMetaData().getTables(null, null, "BILLING", null);
        assertTrue("Billing table should still exist", tables.next());

        tables.close();
        rs.close();
        stmt.close();
    }

    /**
     * Test SQL injection with UNION-based attack payload.
     */
    @Test
    public void testSQLInjectionInStoneNumbers_UnionAttack() throws Exception {
        String sqlInjectionPayload = "5' UNION SELECT Customer_ID, Job_ID FROM Job_Card --";

        setTextFieldValues(
            "CUST001",
            "JOB001",
            "03/01/2024",
            sqlInjectionPayload,
            "8.0",
            "7.5",
            "0.2",
            "0.1",
            "18",
            "40000",
            "500"
        );
        billingInstance.Details.setText("Union attack test");

        // Execute the action
        ActionEvent mockEvent = new ActionEvent(billingInstance.submit, ActionEvent.ACTION_PERFORMED, "submit");
        billingInstance.actionPerformed(mockEvent);

        // Verify the payload was stored as literal data
        Statement stmt = testConnection.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT Stone_Numbers FROM Billing WHERE Bill_Date = '03/01/2024'");

        assertTrue("Record should be inserted", rs.next());
        assertEquals("5' UNION SELECT Customer_ID, Job_ID FROM Job_Card --", rs.getString("Stone_Numbers"));

        rs.close();
        stmt.close();
    }

    /**
     * Test special characters that should be safely escaped/handled.
     */
    @Test
    public void testSpecialCharactersInFields() throws Exception {
        setTextFieldValues(
            "CUST001",
            "JOB001",
            "04/01/2024",
            "10",
            "15.5",
            "14.8",
            "0.3",
            "0.2",
            "22",
            "60000",
            "1500"
        );
        // Test special characters in Details field
        billingInstance.Details.setText("Details with 'quotes', \"double quotes\", and ; semicolon");

        // Execute the action
        ActionEvent mockEvent = new ActionEvent(billingInstance.submit, ActionEvent.ACTION_PERFORMED, "submit");
        billingInstance.actionPerformed(mockEvent);

        // Verify special characters were properly handled
        Statement stmt = testConnection.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT Details FROM Billing WHERE Bill_Date = '04/01/2024'");

        assertTrue("Record should be inserted", rs.next());
        assertEquals("Details with 'quotes', \"double quotes\", and ; semicolon", rs.getString("Details"));

        rs.close();
        stmt.close();
    }

    /**
     * Test SQL injection in multiple fields simultaneously.
     */
    @Test
    public void testSQLInjectionInMultipleFields() throws Exception {
        setTextFieldValues(
            "CUST001",
            "JOB001",
            "05/01/2024",
            "5' OR '1'='1",          // Injection in Stone_Numbers
            "10.5' OR '1'='1",       // Injection in Weight
            "9.8",
            "0.2",
            "0.1",
            "22",
            "50000",
            "1000' OR '1'='1"        // Injection in Discount
        );
        billingInstance.Details.setText("'; DELETE FROM Billing; --");  // Injection in Details

        // Execute the action
        ActionEvent mockEvent = new ActionEvent(billingInstance.submit, ActionEvent.ACTION_PERFORMED, "submit");
        billingInstance.actionPerformed(mockEvent);

        // Verify all payloads were stored as literal data
        Statement stmt = testConnection.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM Billing WHERE Bill_Date = '05/01/2024'");

        assertTrue("Record should be inserted", rs.next());
        assertEquals("5' OR '1'='1", rs.getString("Stone_Numbers"));
        assertEquals("10.5' OR '1'='1", rs.getString("Weight"));
        assertEquals("1000' OR '1'='1", rs.getString("Discount"));
        assertEquals("'; DELETE FROM Billing; --", rs.getString("Details"));

        // Verify table wasn't affected by DELETE attempt
        ResultSet countRs = stmt.executeQuery("SELECT COUNT(*) as total FROM Billing");
        countRs.next();
        assertTrue("Records should still exist", countRs.getInt("total") > 0);

        countRs.close();
        rs.close();
        stmt.close();
    }

    /**
     * Test that empty validation still works correctly.
     * Ensures the security fix didn't break existing validation logic.
     */
    @Test
    public void testValidationForEmptyFields() throws Exception {
        // Set empty Stone_Numbers - should trigger validation
        setTextFieldValues(
            "CUST001",
            "JOB001",
            "06/01/2024",
            "",  // Empty Stone_Numbers
            "10.5",
            "9.8",
            "0.2",
            "0.1",
            "22",
            "50000",
            "1000"
        );
        billingInstance.Details.setText("Test");

        // Execute the action
        ActionEvent mockEvent = new ActionEvent(billingInstance.submit, ActionEvent.ACTION_PERFORMED, "submit");
        billingInstance.actionPerformed(mockEvent);

        // Verify no record was inserted due to validation
        Statement stmt = testConnection.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT COUNT(*) as total FROM Billing WHERE Bill_Date = '06/01/2024'");

        assertTrue(rs.next());
        assertEquals("No record should be inserted with empty Stone_Numbers", 0, rs.getInt("total"));

        rs.close();
        stmt.close();
    }

    /**
     * Test with null byte injection attempt.
     */
    @Test
    public void testNullByteInjection() throws Exception {
        String nullBytePayload = "5\u0000' OR '1'='1";

        setTextFieldValues(
            "CUST001",
            "JOB001",
            "07/01/2024",
            nullBytePayload,
            "10.5",
            "9.8",
            "0.2",
            "0.1",
            "22",
            "50000",
            "1000"
        );
        billingInstance.Details.setText("Null byte test");

        // Execute the action
        ActionEvent mockEvent = new ActionEvent(billingInstance.submit, ActionEvent.ACTION_PERFORMED, "submit");
        billingInstance.actionPerformed(mockEvent);

        // Verify the payload was handled safely
        Statement stmt = testConnection.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT Stone_Numbers FROM Billing WHERE Bill_Date = '07/01/2024'");

        assertTrue("Record should be inserted", rs.next());
        // The null byte and injection attempt should be treated as literal data
        assertNotNull(rs.getString("Stone_Numbers"));

        rs.close();
        stmt.close();
    }

    /**
     * Test with encoding bypass attempts (URL encoding, hex encoding).
     */
    @Test
    public void testEncodingBypassAttempts() throws Exception {
        String encodedPayload = "5%27%20OR%20%271%27%3D%271";  // URL encoded: 5' OR '1'='1

        setTextFieldValues(
            "CUST001",
            "JOB001",
            "08/01/2024",
            encodedPayload,
            "10.5",
            "9.8",
            "0.2",
            "0.1",
            "22",
            "50000",
            "1000"
        );
        billingInstance.Details.setText("Encoding test");

        // Execute the action
        ActionEvent mockEvent = new ActionEvent(billingInstance.submit, ActionEvent.ACTION_PERFORMED, "submit");
        billingInstance.actionPerformed(mockEvent);

        // Verify encoded payload was stored as-is
        Statement stmt = testConnection.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT Stone_Numbers FROM Billing WHERE Bill_Date = '08/01/2024'");

        assertTrue("Record should be inserted", rs.next());
        assertEquals("5%27%20OR%20%271%27%3D%271", rs.getString("Stone_Numbers"));

        rs.close();
        stmt.close();
    }

    /**
     * Helper method to set text field values for testing.
     */
    private void setTextFieldValues(String customerId, String jobId, String billDate,
                                     String stoneNumbers, String weight, String netWeight,
                                     String grossErr, String weightErr, String goldPurity,
                                     String totalPrice, String discount) {
        billingInstance.Customer_Id.setText(customerId);
        billingInstance.Job_Id.setText(jobId);
        billingInstance.Bill_Date.setText(billDate);
        billingInstance.Stone_Numbers.setText(stoneNumbers);
        billingInstance.Weight.setText(weight);
        billingInstance.Net_Weight.setText(netWeight);
        billingInstance.Gross_Err.setText(grossErr);
        billingInstance.Weight_Err.setText(weightErr);
        billingInstance.Gold_Purity.setText(goldPurity);
        billingInstance.Total_Price.setText(totalPrice);
        billingInstance.Discount.setText(discount);
    }
}
