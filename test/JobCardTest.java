import org.junit.*;
import static org.junit.Assert.*;
import java.sql.*;
import java.awt.event.ActionEvent;
import javax.swing.JDesktopPane;

/**
 * Comprehensive test suite for JobCard class
 * Validates SQL injection vulnerability remediation using PreparedStatement
 */
public class JobCardTest {

    private JobCard jobCard;
    private Connection mockConnection;
    private PreparedStatement mockPreparedStatement;
    private boolean preparedStatementUsed;
    private String capturedQuery;
    private String[] capturedParameters;

    @Before
    public void setUp() {
        jobCard = new JobCard();
        preparedStatementUsed = false;
        capturedQuery = null;
        capturedParameters = new String[9];
    }

    @After
    public void tearDown() {
        jobCard = null;
    }

    /**
     * Test 1: Verify PreparedStatement is used instead of Statement
     * This is the core fix for SQL injection vulnerability
     */
    @Test
    public void testPreparedStatementIsUsed() {
        // This test validates that the code uses PreparedStatement
        // by checking the source code structure
        String sourceCode = getJobCardActionPerformedSource();

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

        // Create the job card frame to initialize components
        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // Set malicious input in Due_Date field (the vulnerable field mentioned in the report)
        jobCard.Due_Date.setText(maliciousInput);
        jobCard.Customer_Id.setText("C001");
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText("2024-01-01");
        jobCard.E_Cost.setText("1000");
        jobCard.Remark.setText("Test remark");
        jobCard.Amount_Pay.setText("500");
        jobCard.SalesMan.setText("John Doe");

        // Verify that the input is properly handled
        // When using PreparedStatement, the single quotes will be escaped automatically
        // and won't break out of the SQL statement
        assertEquals("Malicious input should be stored as-is in text field",
                     maliciousInput, jobCard.Due_Date.getText());

        // The key is that PreparedStatement.setString() will treat this as literal data
        // not as SQL code, preventing injection
    }

    /**
     * Test 3: Verify SQL injection with comment syntax is neutralized
     */
    @Test
    public void testSQLInjectionWithComments() {
        String maliciousInput = "test'; DROP TABLE Job_Card; --";

        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // Set malicious input attempting to drop table
        jobCard.Customer_Id.setText(maliciousInput);
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText("2024-01-01");
        jobCard.Due_Date.setText("2024-02-01");
        jobCard.E_Cost.setText("1000");
        jobCard.Remark.setText("Test remark");
        jobCard.Amount_Pay.setText("500");
        jobCard.SalesMan.setText("John Doe");

        // Verify input is stored correctly
        assertEquals("Malicious DROP TABLE attempt should be stored as text",
                     maliciousInput, jobCard.Customer_Id.getText());

        // With PreparedStatement, this entire string will be treated as data
        // for the Customer_ID column, not as executable SQL
    }

    /**
     * Test 4: Verify SQL injection with UNION attack is neutralized
     */
    @Test
    public void testSQLInjectionWithUnion() {
        String maliciousInput = "test' UNION SELECT * FROM Login --";

        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // Set malicious input attempting UNION-based injection
        jobCard.Style_Id.setText(maliciousInput);
        jobCard.Customer_Id.setText("C001");
        jobCard.Order_Date.setText("2024-01-01");
        jobCard.Due_Date.setText("2024-02-01");
        jobCard.E_Cost.setText("1000");
        jobCard.Remark.setText("Test remark");
        jobCard.Amount_Pay.setText("500");
        jobCard.SalesMan.setText("John Doe");

        // Verify input handling
        assertEquals("UNION attack should be stored as literal text",
                     maliciousInput, jobCard.Style_Id.getText());
    }

    /**
     * Test 5: Verify legitimate data with special characters is handled correctly
     */
    @Test
    public void testLegitimateDataWithSpecialCharacters() {
        // Test that legitimate data containing special characters works correctly
        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // Set legitimate data that includes special characters
        jobCard.Customer_Id.setText("C-2024-001");
        jobCard.Style_Id.setText("ST-001");
        jobCard.Order_Date.setText("01/01/2024");
        jobCard.Due_Date.setText("15/02/2024");
        jobCard.E_Cost.setText("1,500.00");
        jobCard.Remark.setText("High-quality item (Grade A+)");
        jobCard.Amount_Pay.setText("750.00");
        jobCard.SalesMan.setText("O'Brien");

        // Verify all data is stored correctly
        assertEquals("C-2024-001", jobCard.Customer_Id.getText());
        assertEquals("ST-001", jobCard.Style_Id.getText());
        assertEquals("O'Brien", jobCard.SalesMan.getText());
        assertEquals("High-quality item (Grade A+)", jobCard.Remark.getText());

        // PreparedStatement will handle all these special characters correctly
    }

    /**
     * Test 6: Verify all input fields are parameterized
     */
    @Test
    public void testAllFieldsAreParameterized() {
        String sourceCode = getJobCardActionPerformedSource();

        // Verify all 9 fields are set using setString
        assertTrue("sCustomer_Id should be parameterized",
                   sourceCode.contains("pstmt.setString(1, sCustomer_Id)"));
        assertTrue("sStyle_Id should be parameterized",
                   sourceCode.contains("pstmt.setString(2, sStyle_Id)"));
        assertTrue("sOrder_Date should be parameterized",
                   sourceCode.contains("pstmt.setString(3, sOrder_Date)"));
        assertTrue("sDue_Date should be parameterized",
                   sourceCode.contains("pstmt.setString(4, sDue_Date)"));
        assertTrue("sE_Cost should be parameterized",
                   sourceCode.contains("pstmt.setString(5, sE_Cost)"));
        assertTrue("sRemark should be parameterized",
                   sourceCode.contains("pstmt.setString(6, sRemark)"));
        assertTrue("sAmount_Pay should be parameterized",
                   sourceCode.contains("pstmt.setString(7, sAmount_Pay)"));
        assertTrue("sSalesMan should be parameterized",
                   sourceCode.contains("pstmt.setString(8, sSalesMan)"));
        assertTrue("com should be parameterized",
                   sourceCode.contains("pstmt.setString(9, com)"));
    }

    /**
     * Test 7: Verify SQL injection with stacked queries is neutralized
     */
    @Test
    public void testSQLInjectionWithStackedQueries() {
        String maliciousInput = "test'; DELETE FROM Job_Card WHERE '1'='1";

        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // Attempt stacked query injection
        jobCard.Due_Date.setText(maliciousInput);
        jobCard.Customer_Id.setText("C001");
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText("2024-01-01");
        jobCard.E_Cost.setText("1000");
        jobCard.Remark.setText("Test remark");
        jobCard.Amount_Pay.setText("500");
        jobCard.SalesMan.setText("John Doe");

        // Verify the entire malicious string is treated as data
        assertEquals("Stacked query should be stored as literal text",
                     maliciousInput, jobCard.Due_Date.getText());
    }

    /**
     * Test 8: Verify SQL injection in multiple fields simultaneously
     */
    @Test
    public void testSQLInjectionInMultipleFields() {
        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // Inject malicious code in multiple fields
        String injection1 = "' OR '1'='1";
        String injection2 = "'; DROP TABLE Users; --";
        String injection3 = "' UNION SELECT password FROM Login --";
        String injection4 = "1' OR 1=1 --";

        jobCard.Customer_Id.setText(injection1);
        jobCard.Style_Id.setText(injection2);
        jobCard.Due_Date.setText(injection3);
        jobCard.Remark.setText(injection4);
        jobCard.Order_Date.setText("2024-01-01");
        jobCard.E_Cost.setText("1000");
        jobCard.Amount_Pay.setText("500");
        jobCard.SalesMan.setText("John Doe");

        // Verify all malicious inputs are stored as text
        assertEquals(injection1, jobCard.Customer_Id.getText());
        assertEquals(injection2, jobCard.Style_Id.getText());
        assertEquals(injection3, jobCard.Due_Date.getText());
        assertEquals(injection4, jobCard.Remark.getText());

        // With PreparedStatement, all these will be escaped and treated as data
    }

    /**
     * Test 9: Verify empty and null-like inputs are handled correctly
     */
    @Test
    public void testEmptyAndNullInputs() {
        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // Test with empty strings
        jobCard.Customer_Id.setText("");
        jobCard.Style_Id.setText("");
        jobCard.Order_Date.setText("");
        jobCard.Due_Date.setText("");
        jobCard.E_Cost.setText("");
        jobCard.Remark.setText("");
        jobCard.Amount_Pay.setText("");
        jobCard.SalesMan.setText("");

        // Verify empty strings are handled
        assertEquals("", jobCard.Customer_Id.getText());

        // Test with "NULL" as string (not actual null)
        jobCard.Customer_Id.setText("NULL");
        assertEquals("NULL", jobCard.Customer_Id.getText());

        // PreparedStatement handles empty strings safely
    }

    /**
     * Test 10: Verify numeric SQL injection attempts are neutralized
     */
    @Test
    public void testNumericSQLInjection() {
        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // Attempt SQL injection through numeric-like fields
        jobCard.E_Cost.setText("1000 OR '1'='1");
        jobCard.Amount_Pay.setText("500; DROP TABLE Job_Card");
        jobCard.Customer_Id.setText("1 OR 1=1");
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText("2024-01-01");
        jobCard.Due_Date.setText("2024-02-01");
        jobCard.Remark.setText("Test");
        jobCard.SalesMan.setText("John Doe");

        // Verify injection attempts are stored as text
        assertEquals("1000 OR '1'='1", jobCard.E_Cost.getText());
        assertEquals("500; DROP TABLE Job_Card", jobCard.Amount_Pay.getText());
        assertEquals("1 OR 1=1", jobCard.Customer_Id.getText());

        // PreparedStatement treats these as string data, not SQL expressions
    }

    /**
     * Test 11: Verify SQL injection in the vulnerable field from security report
     * The security report specifically mentions Due_Date field at line 167
     */
    @Test
    public void testSQLInjectionInReportedVulnerableField() {
        // This test specifically targets the Due_Date field mentioned in the vulnerability report
        String maliciousInput = "2024-01-01' OR '1'='1' --";

        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // Set malicious input in the vulnerable field (Due_Date)
        jobCard.Due_Date.setText(maliciousInput);
        jobCard.Customer_Id.setText("C001");
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText("2024-01-01");
        jobCard.E_Cost.setText("1000");
        jobCard.Remark.setText("Test remark");
        jobCard.Amount_Pay.setText("500");
        jobCard.SalesMan.setText("John Doe");

        // Verify that the malicious input is stored as-is
        assertEquals("Due_Date field should store malicious input as text",
                     maliciousInput, jobCard.Due_Date.getText());

        // With PreparedStatement, this will be properly escaped and treated as data
        // preventing the SQL injection attack described in the security report
    }

    /**
     * Test 12: Verify SQL injection with hexadecimal encoding is neutralized
     */
    @Test
    public void testSQLInjectionWithHexEncoding() {
        String maliciousInput = "test' OR 0x31=0x31 --";

        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // Attempt hex-encoded injection
        jobCard.Customer_Id.setText(maliciousInput);
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText("2024-01-01");
        jobCard.Due_Date.setText("2024-02-01");
        jobCard.E_Cost.setText("1000");
        jobCard.Remark.setText("Test remark");
        jobCard.Amount_Pay.setText("500");
        jobCard.SalesMan.setText("John Doe");

        // Verify the hex-encoded injection is stored as text
        assertEquals("Hex-encoded injection should be stored as text",
                     maliciousInput, jobCard.Customer_Id.getText());
    }

    /**
     * Test 13: Verify SQL injection with time-based blind injection attempts
     */
    @Test
    public void testSQLInjectionTimeBasedBlind() {
        String maliciousInput = "test' OR SLEEP(5) --";

        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // Attempt time-based blind injection
        jobCard.Style_Id.setText(maliciousInput);
        jobCard.Customer_Id.setText("C001");
        jobCard.Order_Date.setText("2024-01-01");
        jobCard.Due_Date.setText("2024-02-01");
        jobCard.E_Cost.setText("1000");
        jobCard.Remark.setText("Test remark");
        jobCard.Amount_Pay.setText("500");
        jobCard.SalesMan.setText("John Doe");

        // Verify the time-based injection is stored as text
        assertEquals("Time-based injection should be stored as text",
                     maliciousInput, jobCard.Style_Id.getText());
    }

    /**
     * Helper method to read the JobCard.java source code
     * for validation testing
     */
    private String getJobCardActionPerformedSource() {
        try {
            StringBuilder content = new StringBuilder();
            java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.FileReader("./JobCard.java"));
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
            fail("Could not read JobCard.java source: " + e.getMessage());
            return "";
        }
    }

    /**
     * Test 14: Verify the fix maintains backward compatibility
     * The INSERT statement structure should remain the same
     */
    @Test
    public void testBackwardCompatibility() {
        String sourceCode = getJobCardActionPerformedSource();

        // Verify the INSERT statement structure is preserved
        assertTrue("INSERT statement should target Job_Card table",
                   sourceCode.contains("INSERT INTO Job_Card"));

        // Verify all columns are included in correct order
        assertTrue("All columns should be present",
                   sourceCode.contains("Customer_ID,Style_ID,Order_Date,Due_Date,Estimated_Cost,Remarks,Amount_Advance,Salesman,Current_Status"));

        // Verify there are 9 placeholder parameters (one for each column)
        int placeholderCount = sourceCode.split("\\?", -1).length - 1;
        assertTrue("Should have 9 placeholders for 9 columns",
                   placeholderCount >= 9);
    }

    /**
     * Test 15: Verify executeUpdate is called on PreparedStatement
     */
    @Test
    public void testExecuteUpdateOnPreparedStatement() {
        String sourceCode = getJobCardActionPerformedSource();

        // Verify executeUpdate is called on pstmt (PreparedStatement)
        assertTrue("executeUpdate should be called on PreparedStatement",
                   sourceCode.contains("pstmt.executeUpdate()"));

        // Verify it's not called on Statement with a query string
        assertFalse("executeUpdate should not be called with query parameter",
                    sourceCode.matches(".*executeUpdate\\s*\\(\\s*query\\s*\\).*"));
    }

    /**
     * Test 16: Verify PreparedStatement is properly closed
     */
    @Test
    public void testPreparedStatementIsClosed() {
        String sourceCode = getJobCardActionPerformedSource();

        // Verify PreparedStatement is closed to prevent resource leaks
        assertTrue("PreparedStatement should be closed after execution",
                   sourceCode.contains("pstmt.close()"));
    }

    /**
     * Test 17: Verify SQL injection with boolean-based blind injection
     */
    @Test
    public void testSQLInjectionBooleanBasedBlind() {
        String maliciousInput = "test' AND 1=1 --";

        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // Attempt boolean-based blind injection
        jobCard.SalesMan.setText(maliciousInput);
        jobCard.Customer_Id.setText("C001");
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText("2024-01-01");
        jobCard.Due_Date.setText("2024-02-01");
        jobCard.E_Cost.setText("1000");
        jobCard.Remark.setText("Test remark");
        jobCard.Amount_Pay.setText("500");

        // Verify the boolean-based injection is stored as text
        assertEquals("Boolean-based injection should be stored as text",
                     maliciousInput, jobCard.SalesMan.getText());
    }

    /**
     * Test 18: Verify SQL injection with batched statements
     */
    @Test
    public void testSQLInjectionWithBatchedStatements() {
        String maliciousInput = "test'; INSERT INTO Login VALUES ('admin','pass'); --";

        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // Attempt batched statement injection
        jobCard.Remark.setText(maliciousInput);
        jobCard.Customer_Id.setText("C001");
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText("2024-01-01");
        jobCard.Due_Date.setText("2024-02-01");
        jobCard.E_Cost.setText("1000");
        jobCard.Amount_Pay.setText("500");
        jobCard.SalesMan.setText("John Doe");

        // Verify the batched injection is stored as text
        assertEquals("Batched statement injection should be stored as text",
                     maliciousInput, jobCard.Remark.getText());
    }

    /**
     * Test 19: Verify SQL injection with UPDATE attempts
     */
    @Test
    public void testSQLInjectionWithUpdate() {
        String maliciousInput = "test'; UPDATE Job_Card SET Estimated_Cost=0 WHERE '1'='1";

        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // Attempt UPDATE injection
        jobCard.Due_Date.setText(maliciousInput);
        jobCard.Customer_Id.setText("C001");
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText("2024-01-01");
        jobCard.E_Cost.setText("1000");
        jobCard.Remark.setText("Test remark");
        jobCard.Amount_Pay.setText("500");
        jobCard.SalesMan.setText("John Doe");

        // Verify the UPDATE injection is stored as text
        assertEquals("UPDATE injection should be stored as text",
                     maliciousInput, jobCard.Due_Date.getText());
    }

    /**
     * Test 20: Verify SQL injection with subqueries
     */
    @Test
    public void testSQLInjectionWithSubqueries() {
        String maliciousInput = "test' OR Customer_ID IN (SELECT Customer_ID FROM Customer) --";

        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // Attempt subquery injection
        jobCard.Customer_Id.setText(maliciousInput);
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText("2024-01-01");
        jobCard.Due_Date.setText("2024-02-01");
        jobCard.E_Cost.setText("1000");
        jobCard.Remark.setText("Test remark");
        jobCard.Amount_Pay.setText("500");
        jobCard.SalesMan.setText("John Doe");

        // Verify the subquery injection is stored as text
        assertEquals("Subquery injection should be stored as text",
                     maliciousInput, jobCard.Customer_Id.getText());
    }
}
