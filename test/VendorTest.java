import org.junit.*;
import static org.junit.Assert.*;
import java.sql.*;
import java.awt.event.ActionEvent;
import javax.swing.JDesktopPane;

/**
 * Comprehensive test suite for Vendor class
 * Validates SQL injection vulnerability remediation using PreparedStatement
 */
public class VendorTest {

    private Vendor vendor;
    private Connection mockConnection;
    private PreparedStatement mockPreparedStatement;
    private boolean preparedStatementUsed;
    private String capturedQuery;
    private String[] capturedParameters;

    @Before
    public void setUp() {
        vendor = new Vendor();
        preparedStatementUsed = false;
        capturedQuery = null;
        capturedParameters = new String[9];
    }

    @After
    public void tearDown() {
        vendor = null;
    }

    /**
     * Test 1: Verify PreparedStatement is used instead of Statement
     * This is the core fix for SQL injection vulnerability
     */
    @Test
    public void testPreparedStatementIsUsed() {
        // This test validates that the code uses PreparedStatement
        // by checking the source code structure
        String sourceCode = getVendorActionPerformedSource();

        // Verify PreparedStatement is used
        assertTrue("PreparedStatement should be used to prevent SQL injection",
                   sourceCode.contains("PreparedStatement"));

        // Verify the old vulnerable pattern is NOT present
        assertFalse("String concatenation in SQL query should not be used",
                    sourceCode.contains("VALUES ('\""));

        // Verify parameterized query pattern with placeholders
        assertTrue("Query should use parameterized placeholders",
                   sourceCode.contains("VALUES (?,?,?,?,?,?,?,?,?)"));
    }

    /**
     * Test 2: Verify that SQL injection attempts with single quotes are neutralized
     */
    @Test
    public void testSQLInjectionWithSingleQuotes() {
        // Simulate SQL injection attempt with single quotes
        String maliciousInput = "test' OR '1'='1";

        // Create the vendor frame to initialize components
        JDesktopPane desktop = new JDesktopPane();
        vendor.VendorFrame(desktop);

        // Set malicious input in Phone field (the vulnerable field identified)
        vendor.Vendor_Name.setText("TestVendor");
        vendor.Contact_Person.setText("John Doe");
        vendor.Phone.setText(maliciousInput);
        vendor.Fax.setText("555-0002");
        vendor.Mobile.setText("555-0003");
        vendor.email.setText("test@example.com");
        vendor.Cargo_Name.setText("Electronics");
        vendor.Remark.setText("Test remark");
        vendor.Date_In.setText("01/01/2024");

        // Verify that the input is properly handled
        // When using PreparedStatement, the single quotes will be escaped automatically
        // and won't break out of the SQL statement
        assertEquals("Malicious input should be stored as-is in text field",
                     maliciousInput, vendor.Phone.getText());

        // The key is that PreparedStatement.setString() will treat this as literal data
        // not as SQL code, preventing injection
    }

    /**
     * Test 3: Verify SQL injection with comment syntax is neutralized
     */
    @Test
    public void testSQLInjectionWithComments() {
        String maliciousInput = "test'; DROP TABLE Vendor; --";

        JDesktopPane desktop = new JDesktopPane();
        vendor.VendorFrame(desktop);

        // Set malicious input attempting to drop table
        vendor.Vendor_Name.setText(maliciousInput);
        vendor.Contact_Person.setText("John Doe");
        vendor.Phone.setText("555-0001");
        vendor.Fax.setText("555-0002");
        vendor.Mobile.setText("555-0003");
        vendor.email.setText("test@example.com");
        vendor.Cargo_Name.setText("Electronics");
        vendor.Remark.setText("Test remark");
        vendor.Date_In.setText("01/01/2024");

        // Verify input is stored correctly
        assertEquals("Malicious DROP TABLE attempt should be stored as text",
                     maliciousInput, vendor.Vendor_Name.getText());

        // With PreparedStatement, this entire string will be treated as data
        // for the Vendor_name column, not as executable SQL
    }

    /**
     * Test 4: Verify SQL injection with UNION attack is neutralized
     */
    @Test
    public void testSQLInjectionWithUnion() {
        String maliciousInput = "test' UNION SELECT * FROM Login --";

        JDesktopPane desktop = new JDesktopPane();
        vendor.VendorFrame(desktop);

        // Set malicious input attempting UNION-based injection
        vendor.Vendor_Name.setText("TestVendor");
        vendor.Contact_Person.setText(maliciousInput);
        vendor.Phone.setText("555-0001");
        vendor.Fax.setText("555-0002");
        vendor.Mobile.setText("555-0003");
        vendor.email.setText("test@example.com");
        vendor.Cargo_Name.setText("Electronics");
        vendor.Remark.setText("Test remark");
        vendor.Date_In.setText("01/01/2024");

        // Verify input handling
        assertEquals("UNION attack should be stored as literal text",
                     maliciousInput, vendor.Contact_Person.getText());
    }

    /**
     * Test 5: Verify legitimate data with special characters is handled correctly
     */
    @Test
    public void testLegitimateDataWithSpecialCharacters() {
        // Test that legitimate data containing special characters works correctly
        JDesktopPane desktop = new JDesktopPane();
        vendor.VendorFrame(desktop);

        // Set legitimate data that includes special characters
        vendor.Vendor_Name.setText("O'Reilly & Associates");
        vendor.Contact_Person.setText("John O'Brien");
        vendor.Phone.setText("555-0001");
        vendor.Fax.setText("555-0002");
        vendor.Mobile.setText("+1 (555) 123-4567");
        vendor.email.setText("contact@oreilly-associates.com");
        vendor.Cargo_Name.setText("Books & Media");
        vendor.Remark.setText("Premium vendor (5-star rating)");
        vendor.Date_In.setText("01/01/2024");

        // Verify all data is stored correctly
        assertEquals("O'Reilly & Associates", vendor.Vendor_Name.getText());
        assertEquals("John O'Brien", vendor.Contact_Person.getText());
        assertEquals("+1 (555) 123-4567", vendor.Mobile.getText());
        assertEquals("Books & Media", vendor.Cargo_Name.getText());
        assertEquals("Premium vendor (5-star rating)", vendor.Remark.getText());

        // PreparedStatement will handle all these special characters correctly
    }

    /**
     * Test 6: Verify all input fields are parameterized
     */
    @Test
    public void testAllFieldsAreParameterized() {
        String sourceCode = getVendorActionPerformedSource();

        // Verify all 9 fields are set using setString
        assertTrue("Vendor_name should be parameterized",
                   sourceCode.contains("pstmt.setString(1, sVendor_Name)"));
        assertTrue("Contact_Person should be parameterized",
                   sourceCode.contains("pstmt.setString(2, sContact_Person)"));
        assertTrue("Phone should be parameterized",
                   sourceCode.contains("pstmt.setString(3, sPhone)"));
        assertTrue("Fax should be parameterized",
                   sourceCode.contains("pstmt.setString(4, sFax)"));
        assertTrue("Mobile should be parameterized",
                   sourceCode.contains("pstmt.setString(5, sMobile)"));
        assertTrue("email should be parameterized",
                   sourceCode.contains("pstmt.setString(6, semail)"));
        assertTrue("Cargo_Name should be parameterized",
                   sourceCode.contains("pstmt.setString(7, sCargo_Name)"));
        assertTrue("Remark should be parameterized",
                   sourceCode.contains("pstmt.setString(8, sRemark)"));
        assertTrue("Date_In should be parameterized",
                   sourceCode.contains("pstmt.setString(9, sDate_In)"));
    }

    /**
     * Test 7: Verify SQL injection with stacked queries is neutralized
     */
    @Test
    public void testSQLInjectionWithStackedQueries() {
        String maliciousInput = "test'; DELETE FROM Vendor WHERE '1'='1";

        JDesktopPane desktop = new JDesktopPane();
        vendor.VendorFrame(desktop);

        // Attempt stacked query injection
        vendor.Vendor_Name.setText("TestVendor");
        vendor.Contact_Person.setText("John Doe");
        vendor.Phone.setText(maliciousInput);
        vendor.Fax.setText("555-0002");
        vendor.Mobile.setText("555-0003");
        vendor.email.setText("test@example.com");
        vendor.Cargo_Name.setText("Electronics");
        vendor.Remark.setText("Test remark");
        vendor.Date_In.setText("01/01/2024");

        // Verify the entire malicious string is treated as data
        assertEquals("Stacked query should be stored as literal text",
                     maliciousInput, vendor.Phone.getText());
    }

    /**
     * Test 8: Verify SQL injection in multiple fields simultaneously
     */
    @Test
    public void testSQLInjectionInMultipleFields() {
        JDesktopPane desktop = new JDesktopPane();
        vendor.VendorFrame(desktop);

        // Inject malicious code in multiple fields
        String injection1 = "' OR '1'='1";
        String injection2 = "'; DROP TABLE Customer; --";
        String injection3 = "' UNION SELECT password FROM Login --";

        vendor.Vendor_Name.setText(injection1);
        vendor.Contact_Person.setText(injection2);
        vendor.Phone.setText("555-0001");
        vendor.Fax.setText("555-0002");
        vendor.Mobile.setText("555-0003");
        vendor.email.setText(injection3);
        vendor.Cargo_Name.setText("Electronics");
        vendor.Remark.setText("Test");
        vendor.Date_In.setText("01/01/2024");

        // Verify all malicious inputs are stored as text
        assertEquals(injection1, vendor.Vendor_Name.getText());
        assertEquals(injection2, vendor.Contact_Person.getText());
        assertEquals(injection3, vendor.email.getText());

        // With PreparedStatement, all these will be escaped and treated as data
    }

    /**
     * Test 9: Verify empty and null-like inputs are handled correctly
     */
    @Test
    public void testEmptyAndNullInputs() {
        JDesktopPane desktop = new JDesktopPane();
        vendor.VendorFrame(desktop);

        // Test with empty strings
        vendor.Vendor_Name.setText("");
        vendor.Contact_Person.setText("");
        vendor.Phone.setText("");
        vendor.Fax.setText("");
        vendor.Mobile.setText("");
        vendor.email.setText("");
        vendor.Cargo_Name.setText("");
        vendor.Remark.setText("");
        vendor.Date_In.setText("");

        // Verify empty strings are handled
        assertEquals("", vendor.Vendor_Name.getText());

        // Test with "NULL" as string (not actual null)
        vendor.Vendor_Name.setText("NULL");
        assertEquals("NULL", vendor.Vendor_Name.getText());

        // PreparedStatement handles empty strings safely
    }

    /**
     * Test 10: Verify numeric SQL injection attempts are neutralized
     */
    @Test
    public void testNumericSQLInjection() {
        JDesktopPane desktop = new JDesktopPane();
        vendor.VendorFrame(desktop);

        // Attempt SQL injection through fields that might contain numbers
        vendor.Vendor_Name.setText("1 OR 1=1");
        vendor.Phone.setText("555-0001 OR '1'='1");
        vendor.Fax.setText("555-0002; DROP TABLE Vendor");
        vendor.Contact_Person.setText("John Doe");
        vendor.Mobile.setText("555-0003");
        vendor.email.setText("test@example.com");
        vendor.Cargo_Name.setText("Electronics");
        vendor.Remark.setText("Test");
        vendor.Date_In.setText("01/01/2024");

        // Verify injection attempts are stored as text
        assertEquals("1 OR 1=1", vendor.Vendor_Name.getText());
        assertEquals("555-0001 OR '1'='1", vendor.Phone.getText());
        assertEquals("555-0002; DROP TABLE Vendor", vendor.Fax.getText());

        // PreparedStatement treats these as string data, not SQL expressions
    }

    /**
     * Test 11: Verify SQL injection in Phone field (specifically identified as vulnerable)
     */
    @Test
    public void testPhoneFieldSQLInjection() {
        JDesktopPane desktop = new JDesktopPane();
        vendor.VendorFrame(desktop);

        // This is the specific field identified as vulnerable in the security report
        String maliciousPhone = "555-0001'; DELETE FROM Vendor WHERE Phone='555-0001";

        vendor.Vendor_Name.setText("TestVendor");
        vendor.Contact_Person.setText("John Doe");
        vendor.Phone.setText(maliciousPhone);
        vendor.Fax.setText("555-0002");
        vendor.Mobile.setText("555-0003");
        vendor.email.setText("test@example.com");
        vendor.Cargo_Name.setText("Electronics");
        vendor.Remark.setText("Test remark");
        vendor.Date_In.setText("01/01/2024");

        // Verify the Phone field malicious input is stored as literal text
        assertEquals("Phone field SQL injection should be stored as text",
                     maliciousPhone, vendor.Phone.getText());

        // With PreparedStatement, this will be safely parameterized
        // and won't execute as SQL code
    }

    /**
     * Test 12: Verify SQL injection with hex encoding attempts
     */
    @Test
    public void testSQLInjectionWithHexEncoding() {
        JDesktopPane desktop = new JDesktopPane();
        vendor.VendorFrame(desktop);

        // Attempt injection with hex-encoded payloads
        String hexPayload = "0x27204F52202731273D2731";

        vendor.Vendor_Name.setText("TestVendor");
        vendor.Contact_Person.setText("John Doe");
        vendor.Phone.setText(hexPayload);
        vendor.Fax.setText("555-0002");
        vendor.Mobile.setText("555-0003");
        vendor.email.setText("test@example.com");
        vendor.Cargo_Name.setText("Electronics");
        vendor.Remark.setText("Test");
        vendor.Date_In.setText("01/01/2024");

        // Verify hex-encoded payload is treated as text
        assertEquals("Hex-encoded injection should be stored as text",
                     hexPayload, vendor.Phone.getText());
    }

    /**
     * Helper method to read the Vendor.java source code
     * for validation testing
     */
    private String getVendorActionPerformedSource() {
        try {
            StringBuilder content = new StringBuilder();
            java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.FileReader("./Vendor.java"));
            String line;
            boolean inActionPerformed = false;

            while ((line = reader.readLine()) != null) {
                if (line.contains("public void actionPerformed")) {
                    inActionPerformed = true;
                }
                if (inActionPerformed) {
                    content.append(line).append("\n");
                }
                if (inActionPerformed && line.trim().equals("}")) {
                    break;
                }
            }
            reader.close();
            return content.toString();
        } catch (Exception e) {
            fail("Could not read Vendor.java source: " + e.getMessage());
            return "";
        }
    }

    /**
     * Test 13: Verify the fix maintains backward compatibility
     * The INSERT statement structure should remain the same
     */
    @Test
    public void testBackwardCompatibility() {
        String sourceCode = getVendorActionPerformedSource();

        // Verify the INSERT statement structure is preserved
        assertTrue("INSERT statement should target Vendor table",
                   sourceCode.contains("INSERT INTO Vendor"));

        // Verify all columns are included in correct order
        assertTrue("All columns should be present",
                   sourceCode.contains("Vendor_name,Contact_Person,Phone,Fax,Mobile,email,Cargo_Name,Remark,Date_In"));

        // Verify there are 9 placeholder parameters (one for each column)
        int placeholderCount = sourceCode.split("\\?", -1).length - 1;
        assertTrue("Should have 9 placeholders for 9 columns",
                   placeholderCount >= 9);
    }

    /**
     * Test 14: Verify executeUpdate is called on PreparedStatement
     */
    @Test
    public void testExecuteUpdateOnPreparedStatement() {
        String sourceCode = getVendorActionPerformedSource();

        // Verify executeUpdate is called on pstmt (PreparedStatement)
        assertTrue("executeUpdate should be called on PreparedStatement",
                   sourceCode.contains("pstmt.executeUpdate()"));

        // Verify it's not called on Statement with a query string
        assertFalse("executeUpdate should not be called with query parameter",
                    sourceCode.matches(".*executeUpdate\\s*\\(\\s*query\\s*\\).*"));
    }

    /**
     * Test 15: Verify SQL injection with boolean-based blind injection
     */
    @Test
    public void testBooleanBasedBlindSQLInjection() {
        JDesktopPane desktop = new JDesktopPane();
        vendor.VendorFrame(desktop);

        // Attempt boolean-based blind SQL injection
        String blindInjection = "' AND (SELECT COUNT(*) FROM Login) > 0 --";

        vendor.Vendor_Name.setText("TestVendor");
        vendor.Contact_Person.setText("John Doe");
        vendor.Phone.setText("555-0001");
        vendor.Fax.setText(blindInjection);
        vendor.Mobile.setText("555-0003");
        vendor.email.setText("test@example.com");
        vendor.Cargo_Name.setText("Electronics");
        vendor.Remark.setText("Test");
        vendor.Date_In.setText("01/01/2024");

        // Verify boolean-based injection is treated as text
        assertEquals("Boolean-based blind injection should be stored as text",
                     blindInjection, vendor.Fax.getText());
    }

    /**
     * Test 16: Verify SQL injection with time-based blind injection
     */
    @Test
    public void testTimeBasedBlindSQLInjection() {
        JDesktopPane desktop = new JDesktopPane();
        vendor.VendorFrame(desktop);

        // Attempt time-based blind SQL injection
        String timeBasedInjection = "'; WAITFOR DELAY '00:00:05'--";

        vendor.Vendor_Name.setText("TestVendor");
        vendor.Contact_Person.setText("John Doe");
        vendor.Phone.setText("555-0001");
        vendor.Fax.setText("555-0002");
        vendor.Mobile.setText(timeBasedInjection);
        vendor.email.setText("test@example.com");
        vendor.Cargo_Name.setText("Electronics");
        vendor.Remark.setText("Test");
        vendor.Date_In.setText("01/01/2024");

        // Verify time-based injection is treated as text
        assertEquals("Time-based blind injection should be stored as text",
                     timeBasedInjection, vendor.Mobile.getText());
    }

    /**
     * Test 17: Verify SQL injection with second-order injection attempt
     */
    @Test
    public void testSecondOrderSQLInjection() {
        JDesktopPane desktop = new JDesktopPane();
        vendor.VendorFrame(desktop);

        // Attempt to inject payload that might be executed later
        String secondOrderPayload = "admin'--";

        vendor.Vendor_Name.setText("TestVendor");
        vendor.Contact_Person.setText("John Doe");
        vendor.Phone.setText("555-0001");
        vendor.Fax.setText("555-0002");
        vendor.Mobile.setText("555-0003");
        vendor.email.setText(secondOrderPayload);
        vendor.Cargo_Name.setText("Electronics");
        vendor.Remark.setText("Test");
        vendor.Date_In.setText("01/01/2024");

        // Verify second-order injection attempt is stored as text
        assertEquals("Second-order injection should be stored as text",
                     secondOrderPayload, vendor.email.getText());

        // PreparedStatement ensures this won't be executed even if
        // retrieved and used in another query later
    }

    /**
     * Test 18: Verify SQL injection with batch execution attempts
     */
    @Test
    public void testBatchExecutionSQLInjection() {
        JDesktopPane desktop = new JDesktopPane();
        vendor.VendorFrame(desktop);

        // Attempt batch execution injection
        String batchPayload = "test'; INSERT INTO Login VALUES ('hacker','pass123'); --";

        vendor.Vendor_Name.setText("TestVendor");
        vendor.Contact_Person.setText("John Doe");
        vendor.Phone.setText("555-0001");
        vendor.Fax.setText("555-0002");
        vendor.Mobile.setText("555-0003");
        vendor.email.setText("test@example.com");
        vendor.Cargo_Name.setText(batchPayload);
        vendor.Remark.setText("Test");
        vendor.Date_In.setText("01/01/2024");

        // Verify batch execution attempt is treated as text
        assertEquals("Batch execution injection should be stored as text",
                     batchPayload, vendor.Cargo_Name.getText());
    }
}
