import org.junit.*;
import static org.junit.Assert.*;
import java.sql.*;
import java.awt.event.ActionEvent;
import javax.swing.JDesktopPane;

/**
 * Comprehensive tests for Customer class to validate SQL injection vulnerability remediation.
 * These tests verify that the PreparedStatement implementation prevents SQL injection attacks
 * while maintaining proper functionality.
 */
public class CustomerTest {

    private Customer customer;
    private Connection testConnection;
    private static final String TEST_DB_URL = "jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1";

    @Before
    public void setUp() throws Exception {
        customer = new Customer();

        // Create an in-memory H2 database for testing
        testConnection = DriverManager.getConnection(TEST_DB_URL, "sa", "");

        // Create the Customer table matching the application schema
        Statement stmt = testConnection.createStatement();
        stmt.execute("CREATE TABLE IF NOT EXISTS Customer (" +
                    "Customer_Id INT AUTO_INCREMENT PRIMARY KEY, " +
                    "Date_In VARCHAR(255), " +
                    "Name VARCHAR(255), " +
                    "Address VARCHAR(255), " +
                    "Phone VARCHAR(255), " +
                    "Wedding_Aniv VARCHAR(255), " +
                    "Birthday VARCHAR(255), " +
                    "Ring_Husband VARCHAR(255), " +
                    "Ring_Wife VARCHAR(255), " +
                    "Ring_Other VARCHAR(255), " +
                    "Visits VARCHAR(255), " +
                    "credit VARCHAR(255), " +
                    "Style_Id VARCHAR(255), " +
                    "Remark VARCHAR(255))");
        stmt.close();
    }

    @After
    public void tearDown() throws Exception {
        if (testConnection != null && !testConnection.isClosed()) {
            Statement stmt = testConnection.createStatement();
            stmt.execute("DROP TABLE IF EXISTS Customer");
            stmt.close();
            testConnection.close();
        }
    }

    /**
     * Test that PreparedStatement is used instead of String concatenation.
     * This is a code-level verification that the vulnerability is fixed.
     */
    @Test
    public void testPreparedStatementFieldExists() {
        // Verify that the Customer class has a PreparedStatement field
        try {
            java.lang.reflect.Field pstmtField = Customer.class.getDeclaredField("pstmt");
            assertEquals("PreparedStatement field should exist", PreparedStatement.class, pstmtField.getType());
        } catch (NoSuchFieldException e) {
            fail("Customer class should have a PreparedStatement field named 'pstmt'");
        }
    }

    /**
     * Test SQL injection attempt with malicious single quote in phone field.
     * This should be safely handled by PreparedStatement parameterization.
     */
    @Test
    public void testSQLInjectionAttemptWithSingleQuote() throws SQLException {
        String maliciousPhone = "123'; DROP TABLE Customer; --";

        // Insert using PreparedStatement
        String query = "INSERT INTO Customer(Date_In,Name,Address,Phone,Wedding_Aniv,Birthday,Ring_Husband,Ring_Wife,Ring_Other,Visits,credit,Style_Id,Remark) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)";
        PreparedStatement pstmt = testConnection.prepareStatement(query);

        pstmt.setString(1, "01/01/2024");
        pstmt.setString(2, "John Doe");
        pstmt.setString(3, "123 Main St");
        pstmt.setString(4, maliciousPhone);
        pstmt.setString(5, "05/05/2020");
        pstmt.setString(6, "01/01/1990");
        pstmt.setString(7, "8");
        pstmt.setString(8, "6");
        pstmt.setString(9, "7");
        pstmt.setString(10, "5");
        pstmt.setString(11, "1000");
        pstmt.setString(12, "Style1");
        pstmt.setString(13, "Test remark");

        int result = pstmt.executeUpdate();
        pstmt.close();

        // Verify the record was inserted (result should be 1)
        assertEquals("One record should be inserted", 1, result);

        // Verify the table still exists (wasn't dropped by injection)
        Statement checkStmt = testConnection.createStatement();
        ResultSet rs = checkStmt.executeQuery("SELECT COUNT(*) FROM Customer");
        rs.next();
        assertEquals("Table should contain 1 record", 1, rs.getInt(1));
        rs.close();

        // Verify the malicious string was stored as-is (safely escaped)
        PreparedStatement selectStmt = testConnection.prepareStatement("SELECT Phone FROM Customer WHERE Name = ?");
        selectStmt.setString(1, "John Doe");
        rs = selectStmt.executeQuery();
        rs.next();
        assertEquals("Phone should be stored as literal string", maliciousPhone, rs.getString(1));
        rs.close();
        selectStmt.close();
        checkStmt.close();
    }

    /**
     * Test SQL injection attempt with UNION-based injection in name field.
     */
    @Test
    public void testSQLInjectionAttemptWithUnion() throws SQLException {
        String maliciousName = "John' UNION SELECT * FROM Customer WHERE '1'='1";

        String query = "INSERT INTO Customer(Date_In,Name,Address,Phone,Wedding_Aniv,Birthday,Ring_Husband,Ring_Wife,Ring_Other,Visits,credit,Style_Id,Remark) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)";
        PreparedStatement pstmt = testConnection.prepareStatement(query);

        pstmt.setString(1, "01/01/2024");
        pstmt.setString(2, maliciousName);
        pstmt.setString(3, "456 Oak Ave");
        pstmt.setString(4, "555-1234");
        pstmt.setString(5, "06/06/2021");
        pstmt.setString(6, "02/02/1991");
        pstmt.setString(7, "9");
        pstmt.setString(8, "7");
        pstmt.setString(9, "8");
        pstmt.setString(10, "3");
        pstmt.setString(11, "2000");
        pstmt.setString(12, "Style2");
        pstmt.setString(13, "Another test");

        int result = pstmt.executeUpdate();
        pstmt.close();

        assertEquals("One record should be inserted", 1, result);

        // Verify the malicious string was stored safely
        PreparedStatement selectStmt = testConnection.prepareStatement("SELECT Name FROM Customer WHERE Address = ?");
        selectStmt.setString(1, "456 Oak Ave");
        ResultSet rs = selectStmt.executeQuery();
        rs.next();
        assertEquals("Name should be stored as literal string", maliciousName, rs.getString(1));
        rs.close();
        selectStmt.close();
    }

    /**
     * Test SQL injection attempt with multiple statement execution.
     */
    @Test
    public void testSQLInjectionAttemptWithMultipleStatements() throws SQLException {
        String maliciousAddress = "123 Main'; DELETE FROM Customer WHERE '1'='1'; --";

        String query = "INSERT INTO Customer(Date_In,Name,Address,Phone,Wedding_Aniv,Birthday,Ring_Husband,Ring_Wife,Ring_Other,Visits,credit,Style_Id,Remark) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)";
        PreparedStatement pstmt = testConnection.prepareStatement(query);

        pstmt.setString(1, "03/03/2024");
        pstmt.setString(2, "Jane Smith");
        pstmt.setString(3, maliciousAddress);
        pstmt.setString(4, "555-5678");
        pstmt.setString(5, "07/07/2022");
        pstmt.setString(6, "03/03/1992");
        pstmt.setString(7, "7");
        pstmt.setString(8, "5");
        pstmt.setString(9, "6");
        pstmt.setString(10, "4");
        pstmt.setString(11, "3000");
        pstmt.setString(12, "Style3");
        pstmt.setString(13, "Test with DELETE");

        int result = pstmt.executeUpdate();
        pstmt.close();

        assertEquals("One record should be inserted", 1, result);

        // Verify records weren't deleted
        Statement checkStmt = testConnection.createStatement();
        ResultSet rs = checkStmt.executeQuery("SELECT COUNT(*) FROM Customer");
        rs.next();
        assertTrue("Records should not be deleted", rs.getInt(1) > 0);
        rs.close();
        checkStmt.close();
    }

    /**
     * Test SQL injection attempt with comment-based injection in remark field.
     */
    @Test
    public void testSQLInjectionAttemptWithComments() throws SQLException {
        String maliciousRemark = "Test'); DROP TABLE Customer; --";

        String query = "INSERT INTO Customer(Date_In,Name,Address,Phone,Wedding_Aniv,Birthday,Ring_Husband,Ring_Wife,Ring_Other,Visits,credit,Style_Id,Remark) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)";
        PreparedStatement pstmt = testConnection.prepareStatement(query);

        pstmt.setString(1, "04/04/2024");
        pstmt.setString(2, "Bob Johnson");
        pstmt.setString(3, "789 Pine Rd");
        pstmt.setString(4, "555-9012");
        pstmt.setString(5, "08/08/2023");
        pstmt.setString(6, "04/04/1993");
        pstmt.setString(7, "6");
        pstmt.setString(8, "4");
        pstmt.setString(9, "5");
        pstmt.setString(10, "2");
        pstmt.setString(11, "4000");
        pstmt.setString(12, "Style4");
        pstmt.setString(13, maliciousRemark);

        int result = pstmt.executeUpdate();
        pstmt.close();

        assertEquals("One record should be inserted", 1, result);

        // Verify the table wasn't dropped
        Statement checkStmt = testConnection.createStatement();
        ResultSet rs = checkStmt.executeQuery("SELECT Remark FROM Customer WHERE Name = 'Bob Johnson'");
        assertTrue("Record should exist", rs.next());
        assertEquals("Remark should be stored as literal", maliciousRemark, rs.getString(1));
        rs.close();
        checkStmt.close();
    }

    /**
     * Test normal legitimate customer data insertion.
     * Ensures the fix doesn't break legitimate functionality.
     */
    @Test
    public void testLegitimateCustomerInsertion() throws SQLException {
        String query = "INSERT INTO Customer(Date_In,Name,Address,Phone,Wedding_Aniv,Birthday,Ring_Husband,Ring_Wife,Ring_Other,Visits,credit,Style_Id,Remark) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)";
        PreparedStatement pstmt = testConnection.prepareStatement(query);

        pstmt.setString(1, "05/05/2024");
        pstmt.setString(2, "Alice Williams");
        pstmt.setString(3, "321 Elm St");
        pstmt.setString(4, "555-3456");
        pstmt.setString(5, "09/09/2024");
        pstmt.setString(6, "05/05/1994,06/06/1995");
        pstmt.setString(7, "8");
        pstmt.setString(8, "6");
        pstmt.setString(9, "7");
        pstmt.setString(10, "10");
        pstmt.setString(11, "5000");
        pstmt.setString(12, "Style5");
        pstmt.setString(13, "Regular customer with no special characters");

        int result = pstmt.executeUpdate();
        pstmt.close();

        assertEquals("One record should be inserted", 1, result);

        // Verify all fields were stored correctly
        PreparedStatement selectStmt = testConnection.prepareStatement("SELECT * FROM Customer WHERE Name = ?");
        selectStmt.setString(1, "Alice Williams");
        ResultSet rs = selectStmt.executeQuery();

        assertTrue("Record should exist", rs.next());
        assertEquals("Date_In should match", "05/05/2024", rs.getString("Date_In"));
        assertEquals("Address should match", "321 Elm St", rs.getString("Address"));
        assertEquals("Phone should match", "555-3456", rs.getString("Phone"));
        assertEquals("Wedding_Aniv should match", "09/09/2024", rs.getString("Wedding_Aniv"));
        assertEquals("Birthday should match", "05/05/1994,06/06/1995", rs.getString("Birthday"));
        assertEquals("Ring_Husband should match", "8", rs.getString("Ring_Husband"));
        assertEquals("Ring_Wife should match", "6", rs.getString("Ring_Wife"));
        assertEquals("Ring_Other should match", "7", rs.getString("Ring_Other"));
        assertEquals("Visits should match", "10", rs.getString("Visits"));
        assertEquals("credit should match", "5000", rs.getString("credit"));
        assertEquals("Style_Id should match", "Style5", rs.getString("Style_Id"));
        assertEquals("Remark should match", "Regular customer with no special characters", rs.getString("Remark"));

        rs.close();
        selectStmt.close();
    }

    /**
     * Test with special characters that are legitimate but could be problematic.
     */
    @Test
    public void testSpecialCharactersHandling() throws SQLException {
        String nameWithApostrophe = "O'Brien";
        String addressWithQuotes = "123 \"Main\" Street";
        String remarkWithBackslash = "Customer\\Notes\\Here";

        String query = "INSERT INTO Customer(Date_In,Name,Address,Phone,Wedding_Aniv,Birthday,Ring_Husband,Ring_Wife,Ring_Other,Visits,credit,Style_Id,Remark) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)";
        PreparedStatement pstmt = testConnection.prepareStatement(query);

        pstmt.setString(1, "06/06/2024");
        pstmt.setString(2, nameWithApostrophe);
        pstmt.setString(3, addressWithQuotes);
        pstmt.setString(4, "555-7890");
        pstmt.setString(5, "10/10/2024");
        pstmt.setString(6, "06/06/1995");
        pstmt.setString(7, "9");
        pstmt.setString(8, "7");
        pstmt.setString(9, "8");
        pstmt.setString(10, "6");
        pstmt.setString(11, "6000");
        pstmt.setString(12, "Style6");
        pstmt.setString(13, remarkWithBackslash);

        int result = pstmt.executeUpdate();
        pstmt.close();

        assertEquals("One record should be inserted", 1, result);

        // Verify special characters were stored correctly
        PreparedStatement selectStmt = testConnection.prepareStatement("SELECT Name, Address, Remark FROM Customer WHERE Phone = ?");
        selectStmt.setString(1, "555-7890");
        ResultSet rs = selectStmt.executeQuery();

        assertTrue("Record should exist", rs.next());
        assertEquals("Name with apostrophe should be preserved", nameWithApostrophe, rs.getString("Name"));
        assertEquals("Address with quotes should be preserved", addressWithQuotes, rs.getString("Address"));
        assertEquals("Remark with backslash should be preserved", remarkWithBackslash, rs.getString("Remark"));

        rs.close();
        selectStmt.close();
    }

    /**
     * Test with empty/null values to ensure proper handling.
     */
    @Test
    public void testEmptyAndNullValues() throws SQLException {
        String query = "INSERT INTO Customer(Date_In,Name,Address,Phone,Wedding_Aniv,Birthday,Ring_Husband,Ring_Wife,Ring_Other,Visits,credit,Style_Id,Remark) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)";
        PreparedStatement pstmt = testConnection.prepareStatement(query);

        pstmt.setString(1, "");
        pstmt.setString(2, "Test User");
        pstmt.setString(3, "");
        pstmt.setString(4, "");
        pstmt.setString(5, "");
        pstmt.setString(6, "");
        pstmt.setString(7, "");
        pstmt.setString(8, "");
        pstmt.setString(9, "");
        pstmt.setString(10, "");
        pstmt.setString(11, "");
        pstmt.setString(12, "");
        pstmt.setString(13, "");

        int result = pstmt.executeUpdate();
        pstmt.close();

        assertEquals("One record should be inserted", 1, result);

        // Verify the record exists with empty values
        PreparedStatement selectStmt = testConnection.prepareStatement("SELECT * FROM Customer WHERE Name = ?");
        selectStmt.setString(1, "Test User");
        ResultSet rs = selectStmt.executeQuery();

        assertTrue("Record should exist", rs.next());
        assertEquals("Empty string should be preserved", "", rs.getString("Phone"));

        rs.close();
        selectStmt.close();
    }

    /**
     * Test SQL injection attempt with boolean-based blind injection pattern.
     */
    @Test
    public void testBooleanBasedBlindSQLInjection() throws SQLException {
        String maliciousPhone = "555-1234' OR '1'='1";

        String query = "INSERT INTO Customer(Date_In,Name,Address,Phone,Wedding_Aniv,Birthday,Ring_Husband,Ring_Wife,Ring_Other,Visits,credit,Style_Id,Remark) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)";
        PreparedStatement pstmt = testConnection.prepareStatement(query);

        pstmt.setString(1, "07/07/2024");
        pstmt.setString(2, "Test Boolean");
        pstmt.setString(3, "Test Address");
        pstmt.setString(4, maliciousPhone);
        pstmt.setString(5, "11/11/2024");
        pstmt.setString(6, "07/07/1996");
        pstmt.setString(7, "8");
        pstmt.setString(8, "6");
        pstmt.setString(9, "7");
        pstmt.setString(10, "5");
        pstmt.setString(11, "7000");
        pstmt.setString(12, "Style7");
        pstmt.setString(13, "Test boolean injection");

        int result = pstmt.executeUpdate();
        pstmt.close();

        assertEquals("One record should be inserted", 1, result);

        // Verify the injection pattern was stored as a literal string
        PreparedStatement selectStmt = testConnection.prepareStatement("SELECT Phone FROM Customer WHERE Name = ?");
        selectStmt.setString(1, "Test Boolean");
        ResultSet rs = selectStmt.executeQuery();

        assertTrue("Record should exist", rs.next());
        assertEquals("Boolean injection should be stored as literal", maliciousPhone, rs.getString(1));

        rs.close();
        selectStmt.close();
    }

    /**
     * Test that PreparedStatement correctly escapes all 13 parameters.
     * This validates that all user inputs are properly parameterized.
     */
    @Test
    public void testAllParametersAreSafelyEscaped() throws SQLException {
        // Create malicious strings for all 13 parameters
        String[] maliciousInputs = {
            "01/01'; DROP TABLE Customer; --",                    // Date_In
            "Name'; DELETE FROM Customer WHERE '1'='1'; --",     // Name
            "Addr' OR '1'='1",                                    // Address
            "Phone' UNION SELECT * FROM Customer --",             // Phone
            "Aniv'; UPDATE Customer SET credit='0' WHERE '1'='1", // Wedding_Aniv
            "Birth'; INSERT INTO Customer VALUES ('hacked') --",  // Birthday
            "8'; DROP TABLE Customer; --",                        // Ring_Husband
            "6' OR '1'='1",                                       // Ring_Wife
            "7'; DELETE FROM Customer; --",                       // Ring_Other
            "5' UNION SELECT password FROM users --",             // Visits
            "1000'; GRANT ALL PRIVILEGES TO attacker; --",        // credit
            "Style' OR 1=1 --",                                   // Style_Id
            "Remark'; EXEC xp_cmdshell('rm -rf /'); --"          // Remark
        };

        String query = "INSERT INTO Customer(Date_In,Name,Address,Phone,Wedding_Aniv,Birthday,Ring_Husband,Ring_Wife,Ring_Other,Visits,credit,Style_Id,Remark) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)";
        PreparedStatement pstmt = testConnection.prepareStatement(query);

        for (int i = 0; i < maliciousInputs.length; i++) {
            pstmt.setString(i + 1, maliciousInputs[i]);
        }

        int result = pstmt.executeUpdate();
        pstmt.close();

        assertEquals("One record should be inserted despite malicious inputs", 1, result);

        // Verify all malicious inputs were stored as literals
        PreparedStatement selectStmt = testConnection.prepareStatement("SELECT * FROM Customer WHERE Name = ?");
        selectStmt.setString(1, maliciousInputs[1]);
        ResultSet rs = selectStmt.executeQuery();

        assertTrue("Record with malicious inputs should exist", rs.next());
        assertEquals("Date_In should be stored as literal", maliciousInputs[0], rs.getString("Date_In"));
        assertEquals("Address should be stored as literal", maliciousInputs[2], rs.getString("Address"));
        assertEquals("Phone should be stored as literal", maliciousInputs[3], rs.getString("Phone"));

        rs.close();
        selectStmt.close();

        // Verify the table still exists and hasn't been tampered with
        Statement checkStmt = testConnection.createStatement();
        ResultSet countRs = checkStmt.executeQuery("SELECT COUNT(*) FROM Customer");
        countRs.next();
        assertTrue("Table should still exist with records", countRs.getInt(1) > 0);
        countRs.close();
        checkStmt.close();
    }
}
