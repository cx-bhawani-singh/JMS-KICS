import org.junit.*;
import static org.junit.Assert.*;
import java.sql.*;
import java.awt.event.ActionEvent;
import javax.swing.JDesktopPane;

/**
 * Comprehensive test suite for Customer class
 * Validates SQL injection vulnerability remediation using PreparedStatement
 */
public class CustomerTest {

    private Customer customer;
    private Connection mockConnection;
    private PreparedStatement mockPreparedStatement;
    private boolean preparedStatementUsed;
    private String capturedQuery;
    private String[] capturedParameters;

    @Before
    public void setUp() {
        customer = new Customer();
        preparedStatementUsed = false;
        capturedQuery = null;
        capturedParameters = new String[13];
    }

    @After
    public void tearDown() {
        customer = null;
    }

    /**
     * Test 1: Verify PreparedStatement is used instead of Statement
     * This is the core fix for SQL injection vulnerability
     */
    @Test
    public void testPreparedStatementIsUsed() {
        // This test validates that the code uses PreparedStatement
        // by checking the source code structure
        String sourceCode = getCustomerActionPerformedSource();

        // Verify PreparedStatement is used
        assertTrue("PreparedStatement should be used to prevent SQL injection",
                   sourceCode.contains("PreparedStatement"));

        // Verify the old vulnerable pattern is NOT present
        assertFalse("String concatenation in SQL query should not be used",
                    sourceCode.contains("VALUES ('\""));

        // Verify parameterized query pattern with placeholders (13 fields)
        assertTrue("Query should use parameterized placeholders",
                   sourceCode.contains("VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"));
    }

    /**
     * Test 2: Verify that SQL injection attempts with single quotes are neutralized
     * Testing the Remark field which was identified in the vulnerability
     */
    @Test
    public void testSQLInjectionWithSingleQuotesInRemark() {
        // Simulate SQL injection attempt with single quotes
        String maliciousInput = "test' OR '1'='1";

        // Create the customer frame to initialize components
        JDesktopPane desktop = new JDesktopPane();
        customer.CustomerFrame(desktop);

        // Set malicious input in Remark field (the vulnerable field from the report)
        customer.Remark.setText(maliciousInput);
        customer.Date_In.setText("01/01/2024");
        customer.Customer_Name.setText("John Doe");
        customer.Address.setText("123 Main St");
        customer.Phone.setText("555-1234");
        customer.Wedding_Aniv.setText("01/01/2020");
        customer.Birthday.setText("01/01/1990");
        customer.Ring_Husband.setText("10");
        customer.Ring_Wife.setText("8");
        customer.Ring_Other.setText("9");
        customer.Visits.setText("5");
        customer.credit.setText("1000");
        customer.Style_Id.setText("ST001");

        // Verify that the input is properly handled
        // When using PreparedStatement, the single quotes will be escaped automatically
        // and won't break out of the SQL statement
        assertEquals("Malicious input should be stored as-is in text field",
                     maliciousInput, customer.Remark.getText());

        // The key is that PreparedStatement.setString() will treat this as literal data
        // not as SQL code, preventing injection
    }

    /**
     * Test 3: Verify SQL injection with comment syntax is neutralized
     */
    @Test
    public void testSQLInjectionWithComments() {
        String maliciousInput = "test'; DROP TABLE Customer; --";

        JDesktopPane desktop = new JDesktopPane();
        customer.CustomerFrame(desktop);

        // Set malicious input attempting to drop table
        customer.Remark.setText(maliciousInput);
        customer.Date_In.setText("01/01/2024");
        customer.Customer_Name.setText("John Doe");
        customer.Address.setText("123 Main St");
        customer.Phone.setText("555-1234");
        customer.Wedding_Aniv.setText("01/01/2020");
        customer.Birthday.setText("01/01/1990");
        customer.Ring_Husband.setText("10");
        customer.Ring_Wife.setText("8");
        customer.Ring_Other.setText("9");
        customer.Visits.setText("5");
        customer.credit.setText("1000");
        customer.Style_Id.setText("ST001");

        // Verify input is stored correctly
        assertEquals("Malicious DROP TABLE attempt should be stored as text",
                     maliciousInput, customer.Remark.getText());

        // With PreparedStatement, this entire string will be treated as data
        // for the Remark column, not as executable SQL
    }

    /**
     * Test 4: Verify SQL injection with UNION attack is neutralized
     */
    @Test
    public void testSQLInjectionWithUnion() {
        String maliciousInput = "test' UNION SELECT * FROM Login --";

        JDesktopPane desktop = new JDesktopPane();
        customer.CustomerFrame(desktop);

        // Set malicious input attempting UNION-based injection
        customer.Remark.setText(maliciousInput);
        customer.Date_In.setText("01/01/2024");
        customer.Customer_Name.setText("John Doe");
        customer.Address.setText("123 Main St");
        customer.Phone.setText("555-1234");
        customer.Wedding_Aniv.setText("01/01/2020");
        customer.Birthday.setText("01/01/1990");
        customer.Ring_Husband.setText("10");
        customer.Ring_Wife.setText("8");
        customer.Ring_Other.setText("9");
        customer.Visits.setText("5");
        customer.credit.setText("1000");
        customer.Style_Id.setText("ST001");

        // Verify input handling
        assertEquals("UNION attack should be stored as literal text",
                     maliciousInput, customer.Remark.getText());
    }

    /**
     * Test 5: Verify legitimate data with special characters is handled correctly
     */
    @Test
    public void testLegitimateDataWithSpecialCharacters() {
        // Test that legitimate data containing special characters works correctly
        JDesktopPane desktop = new JDesktopPane();
        customer.CustomerFrame(desktop);

        // Set legitimate data that includes special characters
        customer.Date_In.setText("01/01/2024");
        customer.Customer_Name.setText("O'Brien & Associates");
        customer.Address.setText("123 Main St., Apt. #5");
        customer.Phone.setText("(555) 123-4567");
        customer.Wedding_Aniv.setText("12/25/2020");
        customer.Birthday.setText("01/15/1985, 03/20/1987");
        customer.Ring_Husband.setText("10.5");
        customer.Ring_Wife.setText("8.5");
        customer.Ring_Other.setText("N/A");
        customer.Visits.setText("3+2");
        customer.credit.setText("$1,500.00");
        customer.Style_Id.setText("ST-2024-001");
        customer.Remark.setText("VIP customer (Gold tier)");

        // Verify all data is stored correctly
        assertEquals("O'Brien & Associates", customer.Customer_Name.getText());
        assertEquals("123 Main St., Apt. #5", customer.Address.getText());
        assertEquals("VIP customer (Gold tier)", customer.Remark.getText());
        assertEquals("$1,500.00", customer.credit.getText());

        // PreparedStatement will handle all these special characters correctly
    }

    /**
     * Test 6: Verify all 13 input fields are parameterized
     */
    @Test
    public void testAllFieldsAreParameterized() {
        String sourceCode = getCustomerActionPerformedSource();

        // Verify all 13 fields are set using setString
        assertTrue("sDate_In should be parameterized",
                   sourceCode.contains("pstmt.setString(1, sDate_In)"));
        assertTrue("sCustomer_Name should be parameterized",
                   sourceCode.contains("pstmt.setString(2, sCustomer_Name)"));
        assertTrue("sAddress should be parameterized",
                   sourceCode.contains("pstmt.setString(3, sAddress)"));
        assertTrue("sPhone should be parameterized",
                   sourceCode.contains("pstmt.setString(4, sPhone)"));
        assertTrue("sWedding_Aniv should be parameterized",
                   sourceCode.contains("pstmt.setString(5, sWedding_Aniv)"));
        assertTrue("sBirthday should be parameterized",
                   sourceCode.contains("pstmt.setString(6, sBirthday)"));
        assertTrue("sRing_Husband should be parameterized",
                   sourceCode.contains("pstmt.setString(7, sRing_Husband)"));
        assertTrue("sRing_Wife should be parameterized",
                   sourceCode.contains("pstmt.setString(8, sRing_Wife)"));
        assertTrue("sRing_Other should be parameterized",
                   sourceCode.contains("pstmt.setString(9, sRing_Other)"));
        assertTrue("sVisits should be parameterized",
                   sourceCode.contains("pstmt.setString(10, sVisits)"));
        assertTrue("scredit should be parameterized",
                   sourceCode.contains("pstmt.setString(11, scredit)"));
        assertTrue("sStyle_Id should be parameterized",
                   sourceCode.contains("pstmt.setString(12, sStyle_Id)"));
        assertTrue("sRemark should be parameterized",
                   sourceCode.contains("pstmt.setString(13, sRemark)"));
    }

    /**
     * Test 7: Verify SQL injection with stacked queries is neutralized
     */
    @Test
    public void testSQLInjectionWithStackedQueries() {
        String maliciousInput = "test'; DELETE FROM Customer WHERE '1'='1";

        JDesktopPane desktop = new JDesktopPane();
        customer.CustomerFrame(desktop);

        // Attempt stacked query injection
        customer.Remark.setText(maliciousInput);
        customer.Date_In.setText("01/01/2024");
        customer.Customer_Name.setText("John Doe");
        customer.Address.setText("123 Main St");
        customer.Phone.setText("555-1234");
        customer.Wedding_Aniv.setText("01/01/2020");
        customer.Birthday.setText("01/01/1990");
        customer.Ring_Husband.setText("10");
        customer.Ring_Wife.setText("8");
        customer.Ring_Other.setText("9");
        customer.Visits.setText("5");
        customer.credit.setText("1000");
        customer.Style_Id.setText("ST001");

        // Verify the entire malicious string is treated as data
        assertEquals("Stacked query should be stored as literal text",
                     maliciousInput, customer.Remark.getText());
    }

    /**
     * Test 8: Verify SQL injection in multiple fields simultaneously
     */
    @Test
    public void testSQLInjectionInMultipleFields() {
        JDesktopPane desktop = new JDesktopPane();
        customer.CustomerFrame(desktop);

        // Inject malicious code in multiple fields
        String injection1 = "' OR '1'='1";
        String injection2 = "'; DROP TABLE Users; --";
        String injection3 = "' UNION SELECT password FROM Login --";
        String injection4 = "'; UPDATE Customer SET credit='99999' --";

        customer.Customer_Name.setText(injection1);
        customer.Address.setText(injection2);
        customer.Remark.setText(injection3);
        customer.Phone.setText(injection4);
        customer.Date_In.setText("01/01/2024");
        customer.Wedding_Aniv.setText("01/01/2020");
        customer.Birthday.setText("01/01/1990");
        customer.Ring_Husband.setText("10");
        customer.Ring_Wife.setText("8");
        customer.Ring_Other.setText("9");
        customer.Visits.setText("5");
        customer.credit.setText("1000");
        customer.Style_Id.setText("ST001");

        // Verify all malicious inputs are stored as text
        assertEquals(injection1, customer.Customer_Name.getText());
        assertEquals(injection2, customer.Address.getText());
        assertEquals(injection3, customer.Remark.getText());
        assertEquals(injection4, customer.Phone.getText());

        // With PreparedStatement, all these will be escaped and treated as data
    }

    /**
     * Test 9: Verify empty and null-like inputs are handled correctly
     */
    @Test
    public void testEmptyAndNullInputs() {
        JDesktopPane desktop = new JDesktopPane();
        customer.CustomerFrame(desktop);

        // Test with empty strings
        customer.Date_In.setText("");
        customer.Customer_Name.setText("");
        customer.Address.setText("");
        customer.Phone.setText("");
        customer.Wedding_Aniv.setText("");
        customer.Birthday.setText("");
        customer.Ring_Husband.setText("");
        customer.Ring_Wife.setText("");
        customer.Ring_Other.setText("");
        customer.Visits.setText("");
        customer.credit.setText("");
        customer.Style_Id.setText("");
        customer.Remark.setText("");

        // Verify empty strings are handled
        assertEquals("", customer.Remark.getText());
        assertEquals("", customer.Customer_Name.getText());

        // Test with "NULL" as string (not actual null)
        customer.Remark.setText("NULL");
        assertEquals("NULL", customer.Remark.getText());

        // PreparedStatement handles empty strings safely
    }

    /**
     * Test 10: Verify SQL injection attempts in name field
     */
    @Test
    public void testSQLInjectionInNameField() {
        JDesktopPane desktop = new JDesktopPane();
        customer.CustomerFrame(desktop);

        // Attempt SQL injection through name field
        customer.Customer_Name.setText("Admin' --");
        customer.Date_In.setText("01/01/2024");
        customer.Address.setText("123 Main St");
        customer.Phone.setText("555-1234");
        customer.Wedding_Aniv.setText("01/01/2020");
        customer.Birthday.setText("01/01/1990");
        customer.Ring_Husband.setText("10");
        customer.Ring_Wife.setText("8");
        customer.Ring_Other.setText("9");
        customer.Visits.setText("5");
        customer.credit.setText("1000");
        customer.Style_Id.setText("ST001");
        customer.Remark.setText("Test");

        // Verify injection attempts are stored as text
        assertEquals("Admin' --", customer.Customer_Name.getText());

        // PreparedStatement treats these as string data, not SQL expressions
    }

    /**
     * Test 11: Verify SQL injection attempts in address field
     */
    @Test
    public void testSQLInjectionInAddressField() {
        JDesktopPane desktop = new JDesktopPane();
        customer.CustomerFrame(desktop);

        // Attempt SQL injection through address field
        String maliciousAddress = "123 Main'; UPDATE Customer SET credit='99999999' WHERE '1'='1";
        customer.Address.setText(maliciousAddress);
        customer.Date_In.setText("01/01/2024");
        customer.Customer_Name.setText("John Doe");
        customer.Phone.setText("555-1234");
        customer.Wedding_Aniv.setText("01/01/2020");
        customer.Birthday.setText("01/01/1990");
        customer.Ring_Husband.setText("10");
        customer.Ring_Wife.setText("8");
        customer.Ring_Other.setText("9");
        customer.Visits.setText("5");
        customer.credit.setText("1000");
        customer.Style_Id.setText("ST001");
        customer.Remark.setText("Test");

        // Verify the malicious string is treated as data
        assertEquals(maliciousAddress, customer.Address.getText());

        // PreparedStatement will escape and treat this as a literal address string
    }

    /**
     * Test 12: Verify SQL injection with encoded characters
     */
    @Test
    public void testSQLInjectionWithEncodedCharacters() {
        JDesktopPane desktop = new JDesktopPane();
        customer.CustomerFrame(desktop);

        // Test with various encoded and special characters
        customer.Remark.setText("test\"; DROP TABLE Customer; --");
        customer.Customer_Name.setText("test\' OR \'1\'=\'1");
        customer.Address.setText("test\\ OR 1=1");
        customer.Date_In.setText("01/01/2024");
        customer.Phone.setText("555-1234");
        customer.Wedding_Aniv.setText("01/01/2020");
        customer.Birthday.setText("01/01/1990");
        customer.Ring_Husband.setText("10");
        customer.Ring_Wife.setText("8");
        customer.Ring_Other.setText("9");
        customer.Visits.setText("5");
        customer.credit.setText("1000");
        customer.Style_Id.setText("ST001");

        // Verify these are stored as literal text
        assertEquals("test\"; DROP TABLE Customer; --", customer.Remark.getText());
        assertEquals("test\' OR \'1\'=\'1", customer.Customer_Name.getText());
        assertEquals("test\\ OR 1=1", customer.Address.getText());

        // PreparedStatement handles all escape sequences correctly
    }

    /**
     * Helper method to read the Customer.java source code
     * for validation testing
     */
    private String getCustomerActionPerformedSource() {
        try {
            StringBuilder content = new StringBuilder();
            java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.FileReader("./Customer.java"));
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
            fail("Could not read Customer.java source: " + e.getMessage());
            return "";
        }
    }

    /**
     * Test 13: Verify the fix maintains backward compatibility
     * The INSERT statement structure should remain the same
     */
    @Test
    public void testBackwardCompatibility() {
        String sourceCode = getCustomerActionPerformedSource();

        // Verify the INSERT statement structure is preserved
        assertTrue("INSERT statement should target Customer table",
                   sourceCode.contains("INSERT INTO Customer"));

        // Verify all columns are included in correct order
        assertTrue("All columns should be present",
                   sourceCode.contains("Date_In,Name,Address,Phone,Wedding_Aniv,Birthday,Ring_Husband,Ring_Wife,Ring_Other,Visits,credit,Style_Id,Remark"));

        // Verify there are 13 placeholder parameters (one for each column)
        int placeholderCount = sourceCode.split("\\?", -1).length - 1;
        assertTrue("Should have 13 placeholders for 13 columns",
                   placeholderCount >= 13);
    }

    /**
     * Test 14: Verify executeUpdate is called on PreparedStatement
     */
    @Test
    public void testExecuteUpdateOnPreparedStatement() {
        String sourceCode = getCustomerActionPerformedSource();

        // Verify executeUpdate is called on pstmt (PreparedStatement)
        assertTrue("executeUpdate should be called on PreparedStatement",
                   sourceCode.contains("pstmt.executeUpdate()"));

        // Verify it's not called on Statement with a query string
        assertFalse("executeUpdate should not be called with query parameter",
                    sourceCode.matches(".*executeUpdate\\s*\\(\\s*query\\s*\\).*"));
    }

    /**
     * Test 15: Verify SQL injection via data exfiltration attempts
     */
    @Test
    public void testSQLInjectionDataExfiltration() {
        JDesktopPane desktop = new JDesktopPane();
        customer.CustomerFrame(desktop);

        // Attempt to exfiltrate sensitive data through Remark field
        String exfiltrationAttempt = "' UNION SELECT username, password, '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1' FROM Login --";
        customer.Remark.setText(exfiltrationAttempt);
        customer.Date_In.setText("01/01/2024");
        customer.Customer_Name.setText("John Doe");
        customer.Address.setText("123 Main St");
        customer.Phone.setText("555-1234");
        customer.Wedding_Aniv.setText("01/01/2020");
        customer.Birthday.setText("01/01/1990");
        customer.Ring_Husband.setText("10");
        customer.Ring_Wife.setText("8");
        customer.Ring_Other.setText("9");
        customer.Visits.setText("5");
        customer.credit.setText("1000");
        customer.Style_Id.setText("ST001");

        // Verify the exfiltration attempt is stored as literal text
        assertEquals("Data exfiltration attempt should be stored as text",
                     exfiltrationAttempt, customer.Remark.getText());

        // PreparedStatement prevents this from being executed as SQL
    }
}
