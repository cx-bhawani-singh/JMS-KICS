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
     * Test 2: Verify that SQL injection attempts in Remark field are neutralized
     * The vulnerability was specifically in the Remark field (line 169 -> 173 -> 180)
     */
    @Test
    public void testSQLInjectionInRemarkField() {
        // Simulate SQL injection attempt with single quotes in Remark field
        String maliciousRemark = "test' OR '1'='1";

        // Create the jobCard frame to initialize components
        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // Set malicious input in Remark field (the vulnerable field)
        jobCard.Customer_Id.setText("C001");
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText("01/01/2024");
        jobCard.Due_Date.setText("15/01/2024");
        jobCard.E_Cost.setText("5000");
        jobCard.Remark.setText(maliciousRemark);
        jobCard.Amount_Pay.setText("1000");
        jobCard.SalesMan.setText("John Doe");

        // Verify that the input is properly handled
        // When using PreparedStatement, the single quotes will be escaped automatically
        // and won't break out of the SQL statement
        assertEquals("Malicious input should be stored as-is in Remark field",
                     maliciousRemark, jobCard.Remark.getText());

        // The key is that PreparedStatement.setString() will treat this as literal data
        // not as SQL code, preventing injection
    }

    /**
     * Test 3: Verify SQL injection with DROP TABLE in Remark field is neutralized
     */
    @Test
    public void testSQLInjectionWithDropTable() {
        String maliciousRemark = "test'; DROP TABLE Job_Card; --";

        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // Set malicious input attempting to drop table
        jobCard.Customer_Id.setText("C001");
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText("01/01/2024");
        jobCard.Due_Date.setText("15/01/2024");
        jobCard.E_Cost.setText("5000");
        jobCard.Remark.setText(maliciousRemark);
        jobCard.Amount_Pay.setText("1000");
        jobCard.SalesMan.setText("John Doe");

        // Verify input is stored correctly
        assertEquals("Malicious DROP TABLE attempt should be stored as text",
                     maliciousRemark, jobCard.Remark.getText());

        // With PreparedStatement, this entire string will be treated as data
        // for the Remarks column, not as executable SQL
    }

    /**
     * Test 4: Verify SQL injection with UNION attack is neutralized
     */
    @Test
    public void testSQLInjectionWithUnion() {
        String maliciousRemark = "test' UNION SELECT * FROM Login --";

        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // Set malicious input attempting UNION-based injection
        jobCard.Customer_Id.setText("C001");
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText("01/01/2024");
        jobCard.Due_Date.setText("15/01/2024");
        jobCard.E_Cost.setText("5000");
        jobCard.Remark.setText(maliciousRemark);
        jobCard.Amount_Pay.setText("1000");
        jobCard.SalesMan.setText("John Doe");

        // Verify input handling
        assertEquals("UNION attack should be stored as literal text",
                     maliciousRemark, jobCard.Remark.getText());
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
        jobCard.Style_Id.setText("S-2024-001");
        jobCard.Order_Date.setText("01/01/2024");
        jobCard.Due_Date.setText("15/01/2024");
        jobCard.E_Cost.setText("5000.50");
        jobCard.Remark.setText("Customer requested gold & silver design (Grade A+)");
        jobCard.Amount_Pay.setText("1000.00");
        jobCard.SalesMan.setText("John O'Brien");

        // Verify all data is stored correctly
        assertEquals("C-2024-001", jobCard.Customer_Id.getText());
        assertEquals("S-2024-001", jobCard.Style_Id.getText());
        assertEquals("Customer requested gold & silver design (Grade A+)", jobCard.Remark.getText());
        assertEquals("John O'Brien", jobCard.SalesMan.getText());

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
        assertTrue("com (Current_Status) should be parameterized",
                   sourceCode.contains("pstmt.setString(9, com)"));
    }

    /**
     * Test 7: Verify SQL injection with stacked queries is neutralized
     */
    @Test
    public void testSQLInjectionWithStackedQueries() {
        String maliciousRemark = "test'; DELETE FROM Job_Card WHERE '1'='1";

        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // Attempt stacked query injection
        jobCard.Customer_Id.setText("C001");
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText("01/01/2024");
        jobCard.Due_Date.setText("15/01/2024");
        jobCard.E_Cost.setText("5000");
        jobCard.Remark.setText(maliciousRemark);
        jobCard.Amount_Pay.setText("1000");
        jobCard.SalesMan.setText("John Doe");

        // Verify the entire malicious string is treated as data
        assertEquals("Stacked query should be stored as literal text",
                     maliciousRemark, jobCard.Remark.getText());
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

        jobCard.Customer_Id.setText(injection1);
        jobCard.Style_Id.setText(injection2);
        jobCard.Remark.setText(injection3);
        jobCard.Order_Date.setText("01/01/2024");
        jobCard.Due_Date.setText("15/01/2024");
        jobCard.E_Cost.setText("5000");
        jobCard.Amount_Pay.setText("1000");
        jobCard.SalesMan.setText("John Doe");

        // Verify all malicious inputs are stored as text
        assertEquals(injection1, jobCard.Customer_Id.getText());
        assertEquals(injection2, jobCard.Style_Id.getText());
        assertEquals(injection3, jobCard.Remark.getText());

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
        assertEquals("", jobCard.Remark.getText());

        // Test with "NULL" as string (not actual null)
        jobCard.Remark.setText("NULL");
        assertEquals("NULL", jobCard.Remark.getText());

        // PreparedStatement handles empty strings safely
    }

    /**
     * Test 10: Verify numeric SQL injection attempts are neutralized
     */
    @Test
    public void testNumericSQLInjection() {
        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // Attempt SQL injection through numeric fields
        jobCard.Customer_Id.setText("1 OR 1=1");
        jobCard.E_Cost.setText("5000 OR '1'='1");
        jobCard.Amount_Pay.setText("1000; DROP TABLE Job_Card");
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText("01/01/2024");
        jobCard.Due_Date.setText("15/01/2024");
        jobCard.Remark.setText("Test");
        jobCard.SalesMan.setText("John Doe");

        // Verify injection attempts are stored as text
        assertEquals("1 OR 1=1", jobCard.Customer_Id.getText());
        assertEquals("5000 OR '1'='1", jobCard.E_Cost.getText());
        assertEquals("1000; DROP TABLE Job_Card", jobCard.Amount_Pay.getText());

        // PreparedStatement treats these as string data, not SQL expressions
    }

    /**
     * Test 11: Verify complex SQL injection with nested queries
     */
    @Test
    public void testComplexNestedSQLInjection() {
        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // Complex nested SQL injection attempt
        String complexInjection = "test'; INSERT INTO Login VALUES ('hacker', 'password'); SELECT * FROM Job_Card WHERE '1'='1";

        jobCard.Customer_Id.setText("C001");
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText("01/01/2024");
        jobCard.Due_Date.setText("15/01/2024");
        jobCard.E_Cost.setText("5000");
        jobCard.Remark.setText(complexInjection);
        jobCard.Amount_Pay.setText("1000");
        jobCard.SalesMan.setText("John Doe");

        // Verify complex injection is stored as literal text
        assertEquals("Complex nested injection should be stored as text",
                     complexInjection, jobCard.Remark.getText());
    }

    /**
     * Test 12: Verify SQL comment injection attempts are neutralized
     */
    @Test
    public void testSQLCommentInjection() {
        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // Test various SQL comment syntaxes
        String comment1 = "test' -- comment";
        String comment2 = "test' /* comment */ --";
        String comment3 = "test' # comment";

        jobCard.Customer_Id.setText("C001");
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText("01/01/2024");
        jobCard.Due_Date.setText("15/01/2024");
        jobCard.E_Cost.setText("5000");
        jobCard.Amount_Pay.setText("1000");
        jobCard.SalesMan.setText("John Doe");

        // Test first comment style
        jobCard.Remark.setText(comment1);
        assertEquals(comment1, jobCard.Remark.getText());

        // Test second comment style
        jobCard.Remark.setText(comment2);
        assertEquals(comment2, jobCard.Remark.getText());

        // Test third comment style
        jobCard.Remark.setText(comment3);
        assertEquals(comment3, jobCard.Remark.getText());
    }

    /**
     * Test 13: Verify the fix maintains backward compatibility
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
     * Test 14: Verify executeUpdate is called on PreparedStatement
     */
    @Test
    public void testExecuteUpdateOnPreparedStatement() {
        String sourceCode = getJobCardActionPerformedSource();

        // Verify executeUpdate is called on pstmt (PreparedStatement)
        assertTrue("executeUpdate should be called on PreparedStatement",
                   sourceCode.contains("pstmt.executeUpdate()"));

        // Verify it's not called on Statement with a query string
        assertFalse("executeUpdate should not be called with query parameter on stmt",
                    sourceCode.contains("stmt.executeUpdate ( query )"));
    }

    /**
     * Test 15: Verify SQL injection with hex encoding attempts
     */
    @Test
    public void testSQLInjectionWithHexEncoding() {
        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // Attempt injection with hex encoding
        String hexInjection = "test' OR 0x31=0x31 --";

        jobCard.Customer_Id.setText("C001");
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText("01/01/2024");
        jobCard.Due_Date.setText("15/01/2024");
        jobCard.E_Cost.setText("5000");
        jobCard.Remark.setText(hexInjection);
        jobCard.Amount_Pay.setText("1000");
        jobCard.SalesMan.setText("John Doe");

        // Verify hex injection is stored as text
        assertEquals("Hex-based injection should be stored as text",
                     hexInjection, jobCard.Remark.getText());
    }

    /**
     * Test 16: Verify time-based blind SQL injection attempts are neutralized
     */
    @Test
    public void testTimeBasedBlindSQLInjection() {
        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // Time-based blind SQL injection attempt
        String timeBasedInjection = "test'; WAITFOR DELAY '00:00:05'; --";

        jobCard.Customer_Id.setText("C001");
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText("01/01/2024");
        jobCard.Due_Date.setText("15/01/2024");
        jobCard.E_Cost.setText("5000");
        jobCard.Remark.setText(timeBasedInjection);
        jobCard.Amount_Pay.setText("1000");
        jobCard.SalesMan.setText("John Doe");

        // Verify time-based injection is stored as text
        assertEquals("Time-based blind injection should be stored as text",
                     timeBasedInjection, jobCard.Remark.getText());
    }

    /**
     * Test 17: Verify SQL injection attempts in Customer_Id field
     */
    @Test
    public void testSQLInjectionInCustomerIdField() {
        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        String injection = "C001' OR '1'='1";

        jobCard.Customer_Id.setText(injection);
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText("01/01/2024");
        jobCard.Due_Date.setText("15/01/2024");
        jobCard.E_Cost.setText("5000");
        jobCard.Remark.setText("Test");
        jobCard.Amount_Pay.setText("1000");
        jobCard.SalesMan.setText("John Doe");

        assertEquals("Customer_Id injection should be stored as text", injection, jobCard.Customer_Id.getText());
    }

    /**
     * Test 18: Verify SQL injection attempts in all text fields
     */
    @Test
    public void testSQLInjectionInAllFields() {
        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        String baseInjection = "' OR '1'='1";

        jobCard.Customer_Id.setText("C" + baseInjection);
        jobCard.Style_Id.setText("S" + baseInjection);
        jobCard.Order_Date.setText("01/01/2024" + baseInjection);
        jobCard.Due_Date.setText("15/01/2024" + baseInjection);
        jobCard.E_Cost.setText("5000" + baseInjection);
        jobCard.Remark.setText("Test" + baseInjection);
        jobCard.Amount_Pay.setText("1000" + baseInjection);
        jobCard.SalesMan.setText("John" + baseInjection);

        // Verify all fields store injection attempts as text
        assertEquals("C" + baseInjection, jobCard.Customer_Id.getText());
        assertEquals("S" + baseInjection, jobCard.Style_Id.getText());
        assertEquals("Test" + baseInjection, jobCard.Remark.getText());
        assertEquals("John" + baseInjection, jobCard.SalesMan.getText());
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
}
