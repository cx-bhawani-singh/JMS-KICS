import org.junit.*;
import static org.junit.Assert.*;
import java.sql.*;
import java.awt.event.ActionEvent;
import javax.swing.JTextField;
import java.lang.reflect.Field;

/**
 * Comprehensive test suite for Vendor class SQL injection vulnerability fix.
 * Tests verify that PreparedStatement is used to prevent SQL injection attacks.
 */
public class VendorTest {

    private Vendor vendor;
    private Connection testConnection;
    private static final String TEST_DB_URL = "jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1";

    @Before
    public void setUp() throws Exception {
        // Initialize H2 in-memory database for testing
        Class.forName("org.h2.Driver");
        testConnection = DriverManager.getConnection(TEST_DB_URL, "sa", "");

        // Create Vendor table
        Statement stmt = testConnection.createStatement();
        stmt.execute("CREATE TABLE IF NOT EXISTS Vendor (" +
                    "Vendor_id INT AUTO_INCREMENT PRIMARY KEY, " +
                    "Vendor_name VARCHAR(255), " +
                    "Contact_Person VARCHAR(100), " +
                    "Phone VARCHAR(20), " +
                    "Fax VARCHAR(20), " +
                    "Mobile VARCHAR(20), " +
                    "email VARCHAR(100), " +
                    "Cargo_Name VARCHAR(100), " +
                    "Remark VARCHAR(255), " +
                    "Date_In VARCHAR(20))");
        stmt.close();

        // Initialize Vendor instance
        vendor = new Vendor();

        // Use reflection to set the connection for testing
        Field conField = Vendor.class.getDeclaredField("con");
        conField.setAccessible(true);
        conField.set(vendor, testConnection);
    }

    @After
    public void tearDown() throws Exception {
        if (testConnection != null && !testConnection.isClosed()) {
            Statement stmt = testConnection.createStatement();
            stmt.execute("DROP TABLE IF EXISTS Vendor");
            stmt.close();
            testConnection.close();
        }
    }

    /**
     * Test normal input insertion - validates basic functionality works
     */
    @Test
    public void testNormalVendorInsertion() throws Exception {
        // Setup normal input data
        setVendorFields("ABC Corp", "John Doe", "123-456-7890",
                       "123-456-7891", "987-654-3210", "john@abc.com",
                       "Electronics", "Reliable vendor", "2024-03-13");

        // Trigger the action - normally this would be through UI
        // For testing, we'll directly test the insertion logic
        int recordsBefore = countVendorRecords();

        // Simulate action event
        vendor.actionPerformed(new ActionEvent(vendor, ActionEvent.ACTION_PERFORMED, "submit"));

        int recordsAfter = countVendorRecords();

        // Verify record was inserted
        assertEquals("One record should be inserted", recordsBefore + 1, recordsAfter);

        // Verify data integrity
        PreparedStatement pstmt = testConnection.prepareStatement(
            "SELECT * FROM Vendor WHERE Vendor_name = ?");
        pstmt.setString(1, "ABC Corp");
        ResultSet rs = pstmt.executeQuery();

        assertTrue("Record should exist", rs.next());
        assertEquals("John Doe", rs.getString("Contact_Person"));
        assertEquals("123-456-7890", rs.getString("Phone"));

        rs.close();
        pstmt.close();
    }

    /**
     * Test SQL injection attempt via single quote - should be safely handled
     */
    @Test
    public void testSQLInjectionWithSingleQuote() throws Exception {
        // Attempt SQL injection with single quote
        String maliciousInput = "'; DROP TABLE Vendor; --";

        setVendorFields(maliciousInput, "Contact", "Phone",
                       "Fax", "Mobile", "email@test.com",
                       "Cargo", "Remark", "2024-03-13");

        int recordsBefore = countVendorRecords();

        // This should safely insert the malicious string as data, not execute it
        vendor.actionPerformed(new ActionEvent(vendor, ActionEvent.ACTION_PERFORMED, "submit"));

        // Verify table still exists and record was inserted safely
        assertTrue("Vendor table should still exist", tableExists("Vendor"));

        int recordsAfter = countVendorRecords();
        assertEquals("Record should be inserted safely", recordsBefore + 1, recordsAfter);

        // Verify the malicious string was stored as literal data
        PreparedStatement pstmt = testConnection.prepareStatement(
            "SELECT Vendor_name FROM Vendor WHERE Vendor_name = ?");
        pstmt.setString(1, maliciousInput);
        ResultSet rs = pstmt.executeQuery();

        assertTrue("Malicious input should be stored as data", rs.next());
        assertEquals("Input should match exactly", maliciousInput, rs.getString("Vendor_name"));

        rs.close();
        pstmt.close();
    }

    /**
     * Test SQL injection attempt via UNION attack - should be safely handled
     */
    @Test
    public void testSQLInjectionUnionAttack() throws Exception {
        // Attempt UNION-based SQL injection
        String maliciousInput = "' UNION SELECT * FROM Vendor WHERE '1'='1";

        setVendorFields("NormalVendor", maliciousInput, "Phone",
                       "Fax", "Mobile", "email@test.com",
                       "Cargo", "Remark", "2024-03-13");

        int recordsBefore = countVendorRecords();

        vendor.actionPerformed(new ActionEvent(vendor, ActionEvent.ACTION_PERFORMED, "submit"));

        int recordsAfter = countVendorRecords();

        // Should insert exactly one record
        assertEquals("Only one record should be inserted", recordsBefore + 1, recordsAfter);

        // Verify the injection attempt was stored as literal string
        PreparedStatement pstmt = testConnection.prepareStatement(
            "SELECT Contact_Person FROM Vendor WHERE Contact_Person = ?");
        pstmt.setString(1, maliciousInput);
        ResultSet rs = pstmt.executeQuery();

        assertTrue("Injection attempt should be stored as data", rs.next());
        assertEquals(maliciousInput, rs.getString("Contact_Person"));

        rs.close();
        pstmt.close();
    }

    /**
     * Test SQL injection with comment injection - should be safely handled
     */
    @Test
    public void testSQLInjectionWithComment() throws Exception {
        // Attempt to use SQL comment to bypass validation
        String maliciousInput = "admin'-- ";

        setVendorFields(maliciousInput, "Contact", "Phone",
                       "Fax", "Mobile", "email@test.com",
                       "Cargo", "Remark", "2024-03-13");

        int recordsBefore = countVendorRecords();

        vendor.actionPerformed(new ActionEvent(vendor, ActionEvent.ACTION_PERFORMED, "submit"));

        int recordsAfter = countVendorRecords();
        assertEquals("Record should be inserted", recordsBefore + 1, recordsAfter);

        // Verify comment was treated as literal data
        PreparedStatement pstmt = testConnection.prepareStatement(
            "SELECT Vendor_name FROM Vendor WHERE Vendor_name = ?");
        pstmt.setString(1, maliciousInput);
        ResultSet rs = pstmt.executeQuery();

        assertTrue("Comment injection should be stored as data", rs.next());
        assertEquals(maliciousInput, rs.getString("Vendor_name"));

        rs.close();
        pstmt.close();
    }

    /**
     * Test SQL injection with batch statement - should be safely handled
     */
    @Test
    public void testSQLInjectionBatchStatement() throws Exception {
        // Attempt to inject multiple statements
        String maliciousInput = "'; DELETE FROM Vendor WHERE '1'='1";

        setVendorFields("Vendor1", "Contact1", "Phone1",
                       "Fax1", maliciousInput, "email@test.com",
                       "Cargo1", "Remark1", "2024-03-13");

        // Insert a record first to verify it's not deleted
        setVendorFields("SafeVendor", "SafeContact", "SafePhone",
                       "SafeFax", "SafeMobile", "safe@test.com",
                       "SafeCargo", "SafeRemark", "2024-03-13");
        vendor.actionPerformed(new ActionEvent(vendor, ActionEvent.ACTION_PERFORMED, "submit"));

        int recordsBefore = countVendorRecords();

        // Now attempt injection
        setVendorFields("Vendor1", "Contact1", "Phone1",
                       "Fax1", maliciousInput, "email@test.com",
                       "Cargo1", "Remark1", "2024-03-13");
        vendor.actionPerformed(new ActionEvent(vendor, ActionEvent.ACTION_PERFORMED, "submit"));

        int recordsAfter = countVendorRecords();

        // Should add one record, not delete any
        assertEquals("Should insert one record without deletion", recordsBefore + 1, recordsAfter);

        // Verify the safe record still exists
        PreparedStatement pstmt = testConnection.prepareStatement(
            "SELECT COUNT(*) FROM Vendor WHERE Vendor_name = ?");
        pstmt.setString(1, "SafeVendor");
        ResultSet rs = pstmt.executeQuery();
        rs.next();
        assertEquals("Safe record should not be deleted", 1, rs.getInt(1));

        rs.close();
        pstmt.close();
    }

    /**
     * Test with special characters that should be handled safely
     */
    @Test
    public void testSpecialCharactersHandling() throws Exception {
        // Test various special characters
        String specialChars = "O'Reilly & Sons <script>alert('xss')</script>";

        setVendorFields(specialChars, "Contact", "Phone",
                       "Fax", "Mobile", "email@test.com",
                       "Cargo", "Remark", "2024-03-13");

        int recordsBefore = countVendorRecords();

        vendor.actionPerformed(new ActionEvent(vendor, ActionEvent.ACTION_PERFORMED, "submit"));

        int recordsAfter = countVendorRecords();
        assertEquals("Record with special chars should be inserted", recordsBefore + 1, recordsAfter);

        // Verify special characters are preserved
        PreparedStatement pstmt = testConnection.prepareStatement(
            "SELECT Vendor_name FROM Vendor WHERE Vendor_name = ?");
        pstmt.setString(1, specialChars);
        ResultSet rs = pstmt.executeQuery();

        assertTrue("Record should exist", rs.next());
        assertEquals("Special characters should be preserved", specialChars, rs.getString("Vendor_name"));

        rs.close();
        pstmt.close();
    }

    /**
     * Test with null values - edge case handling
     */
    @Test
    public void testNullValueHandling() throws Exception {
        // Set some fields to empty strings (simulating empty text fields)
        setVendorFields("", "", "", "", "", "", "", "", "");

        int recordsBefore = countVendorRecords();

        vendor.actionPerformed(new ActionEvent(vendor, ActionEvent.ACTION_PERFORMED, "submit"));

        int recordsAfter = countVendorRecords();
        assertEquals("Empty values should be inserted", recordsBefore + 1, recordsAfter);
    }

    /**
     * Test with very long input strings - boundary testing
     */
    @Test
    public void testLongInputStrings() throws Exception {
        // Create a string near the field limit
        StringBuilder longString = new StringBuilder();
        for (int i = 0; i < 250; i++) {
            longString.append("A");
        }

        setVendorFields(longString.toString(), "Contact", "Phone",
                       "Fax", "Mobile", "email@test.com",
                       "Cargo", "Remark", "2024-03-13");

        int recordsBefore = countVendorRecords();

        vendor.actionPerformed(new ActionEvent(vendor, ActionEvent.ACTION_PERFORMED, "submit"));

        int recordsAfter = countVendorRecords();
        assertEquals("Long input should be inserted", recordsBefore + 1, recordsAfter);
    }

    // Helper methods

    /**
     * Sets all vendor text fields using reflection to simulate user input
     */
    private void setVendorFields(String vendorName, String contactPerson, String phone,
                                 String fax, String mobile, String email,
                                 String cargoName, String remark, String dateIn) throws Exception {
        setTextField("Vendor_Name", vendorName);
        setTextField("Contact_Person", contactPerson);
        setTextField("Phone", phone);
        setTextField("Fax", fax);
        setTextField("Mobile", mobile);
        setTextField("email", email);
        setTextField("Cargo_Name", cargoName);
        setTextField("Remark", remark);
        setTextField("Date_In", dateIn);
    }

    /**
     * Sets a text field value using reflection
     */
    private void setTextField(String fieldName, String value) throws Exception {
        Field field = Vendor.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        JTextField textField = (JTextField) field.get(vendor);
        textField.setText(value);
    }

    /**
     * Counts the number of records in Vendor table
     */
    private int countVendorRecords() throws SQLException {
        Statement stmt = testConnection.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM Vendor");
        rs.next();
        int count = rs.getInt(1);
        rs.close();
        stmt.close();
        return count;
    }

    /**
     * Checks if a table exists in the database
     */
    private boolean tableExists(String tableName) {
        try {
            DatabaseMetaData meta = testConnection.getMetaData();
            ResultSet rs = meta.getTables(null, null, tableName.toUpperCase(), new String[]{"TABLE"});
            boolean exists = rs.next();
            rs.close();
            return exists;
        } catch (SQLException e) {
            return false;
        }
    }
}
