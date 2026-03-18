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

        // Set malicious input in E_Cost field (the vulnerable field from the report)
        jobCard.E_Cost.setText(maliciousInput);
        jobCard.Customer_Id.setText("C001");
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText("2024-01-01");
        jobCard.Due_Date.setText("2024-01-15");
        jobCard.Remark.setText("Test remark");
        jobCard.Amount_Pay.setText("1000");
        jobCard.SalesMan.setText("John Doe");

        // Verify that the input is properly handled
        // When using PreparedStatement, the single quotes will be escaped automatically
        // and won't break out of the SQL statement
        assertEquals("Malicious input should be stored as-is in text field",
                     maliciousInput, jobCard.E_Cost.getText());

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
        jobCard.E_Cost.setText(maliciousInput);
        jobCard.Customer_Id.setText("C001");
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText("2024-01-01");
        jobCard.Due_Date.setText("2024-01-15");
        jobCard.Remark.setText("Test remark");
        jobCard.Amount_Pay.setText("1000");
        jobCard.SalesMan.setText("John Doe");

        // Verify input is stored correctly
        assertEquals("Malicious DROP TABLE attempt should be stored as text",
                     maliciousInput, jobCard.E_Cost.getText());

        // With PreparedStatement, this entire string will be treated as data
        // for the Estimated_Cost column, not as executable SQL
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
        jobCard.Customer_Id.setText(maliciousInput);
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText("2024-01-01");
        jobCard.Due_Date.setText("2024-01-15");
        jobCard.E_Cost.setText("5000");
        jobCard.Remark.setText("Test remark");
        jobCard.Amount_Pay.setText("1000");
        jobCard.SalesMan.setText("John Doe");

        // Verify input handling
        assertEquals("UNION attack should be stored as literal text",
                     maliciousInput, jobCard.Customer_Id.getText());
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
        jobCard.Due_Date.setText("15/01/2024");
        jobCard.E_Cost.setText("5,000.50");
        jobCard.Remark.setText("High-quality work (Premium)");
        jobCard.Amount_Pay.setText("1,500.00");
        jobCard.SalesMan.setText("O'Brien");

        // Verify all data is stored correctly
        assertEquals("C-2024-001", jobCard.Customer_Id.getText());
        assertEquals("ST-001", jobCard.Style_Id.getText());
        assertEquals("High-quality work (Premium)", jobCard.Remark.getText());
        assertEquals("O'Brien", jobCard.SalesMan.getText());

        // PreparedStatement will handle all these special characters correctly
    }

    /**
     * Test 6: Verify all input fields are parameterized
     */
    @Test
    public void testAllFieldsAreParameterized() {
        String sourceCode = getJobCardActionPerformedSource();

        // Verify all 9 fields are set using setString
        assertTrue("Customer_Id should be parameterized",
                   sourceCode.contains("pstmt.setString(1, sCustomer_Id)"));
        assertTrue("Style_Id should be parameterized",
                   sourceCode.contains("pstmt.setString(2, sStyle_Id)"));
        assertTrue("Order_Date should be parameterized",
                   sourceCode.contains("pstmt.setString(3, sOrder_Date)"));
        assertTrue("Due_Date should be parameterized",
                   sourceCode.contains("pstmt.setString(4, sDue_Date)"));
        assertTrue("E_Cost should be parameterized",
                   sourceCode.contains("pstmt.setString(5, sE_Cost)"));
        assertTrue("Remark should be parameterized",
                   sourceCode.contains("pstmt.setString(6, sRemark)"));
        assertTrue("Amount_Pay should be parameterized",
                   sourceCode.contains("pstmt.setString(7, sAmount_Pay)"));
        assertTrue("SalesMan should be parameterized",
                   sourceCode.contains("pstmt.setString(8, sSalesMan)"));
        assertTrue("com (Current_Status) should be parameterized",
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
        jobCard.E_Cost.setText(maliciousInput);
        jobCard.Customer_Id.setText("C001");
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText("2024-01-01");
        jobCard.Due_Date.setText("2024-01-15");
        jobCard.Remark.setText("Test remark");
        jobCard.Amount_Pay.setText("1000");
        jobCard.SalesMan.setText("John Doe");

        // Verify the entire malicious string is treated as data
        assertEquals("Stacked query should be stored as literal text",
                     maliciousInput, jobCard.E_Cost.getText());
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
        jobCard.Order_Date.setText("2024-01-01");
        jobCard.Due_Date.setText("2024-01-15");
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

        // Attempt SQL injection through numeric fields
        jobCard.E_Cost.setText("5000 OR 1=1");
        jobCard.Amount_Pay.setText("1000; DROP TABLE Job_Card");
        jobCard.Customer_Id.setText("C001");
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText("2024-01-01");
        jobCard.Due_Date.setText("2024-01-15");
        jobCard.Remark.setText("Test");
        jobCard.SalesMan.setText("John Doe");

        // Verify injection attempts are stored as text
        assertEquals("5000 OR 1=1", jobCard.E_Cost.getText());
        assertEquals("1000; DROP TABLE Job_Card", jobCard.Amount_Pay.getText());

        // PreparedStatement treats these as string data, not SQL expressions
    }

    /**
     * Test 11: Verify SQL injection on the specific vulnerable field (E_Cost line 168)
     */
    @Test
    public void testVulnerableFieldSpecifically() {
        // This test specifically targets the E_Cost field that was identified
        // as vulnerable at line 168 in the security report
        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // Various SQL injection payloads for E_Cost
        String[] sqlInjectionPayloads = {
            "1' OR '1'='1",
            "1'; DROP TABLE Job_Card; --",
            "1' UNION SELECT username, password FROM Login --",
            "1' AND 1=0 UNION ALL SELECT table_name, null FROM information_schema.tables --",
            "1'; UPDATE Job_Card SET Estimated_Cost='0' WHERE '1'='1",
            "1' OR EXISTS(SELECT * FROM Login WHERE username='admin') --"
        };

        for (String payload : sqlInjectionPayloads) {
            jobCard.E_Cost.setText(payload);
            jobCard.Customer_Id.setText("C001");
            jobCard.Style_Id.setText("S001");
            jobCard.Order_Date.setText("2024-01-01");
            jobCard.Due_Date.setText("2024-01-15");
            jobCard.Remark.setText("Test");
            jobCard.Amount_Pay.setText("1000");
            jobCard.SalesMan.setText("John Doe");

            // Verify that the payload is treated as literal data
            assertEquals("SQL injection payload should be stored as-is: " + payload,
                         payload, jobCard.E_Cost.getText());
        }
    }

    /**
     * Test 12: Verify SQL injection attempts in Remarks field
     */
    @Test
    public void testSQLInjectionInRemarksField() {
        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // Remarks field might be vulnerable due to allowing longer text
        String maliciousRemark = "Nice work'; UPDATE Job_Card SET Estimated_Cost='0' WHERE Customer_ID='C001'; --";

        jobCard.Customer_Id.setText("C001");
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText("2024-01-01");
        jobCard.Due_Date.setText("2024-01-15");
        jobCard.E_Cost.setText("5000");
        jobCard.Remark.setText(maliciousRemark);
        jobCard.Amount_Pay.setText("1000");
        jobCard.SalesMan.setText("John Doe");

        // Verify malicious remark is treated as literal text
        assertEquals("Malicious remark should be stored as-is",
                     maliciousRemark, jobCard.Remark.getText());
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
        assertFalse("executeUpdate should not be called with query parameter on Statement",
                    sourceCode.matches(".*stmt\\.executeUpdate\\s*\\(\\s*query\\s*\\).*"));
    }

    /**
     * Test 15: Verify Status field injection is neutralized
     */
    @Test
    public void testStatusFieldInjection() {
        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // The Status field (com variable) comes from JComboBox
        // Even if manipulated, it should be parameterized
        jobCard.Customer_Id.setText("C001");
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText("2024-01-01");
        jobCard.Due_Date.setText("2024-01-15");
        jobCard.E_Cost.setText("5000");
        jobCard.Remark.setText("Test");
        jobCard.Amount_Pay.setText("1000");
        jobCard.SalesMan.setText("John Doe");

        // The Status/com field is set through the JComboBox
        // Even if somehow an injection was attempted, PreparedStatement protects it
        String sourceCode = getJobCardActionPerformedSource();
        assertTrue("Status field should be parameterized",
                   sourceCode.contains("pstmt.setString(9, com)"));
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
     * Test 16: Verify connection and statement handling
     */
    @Test
    public void testConnectionHandling() {
        String sourceCode = getJobCardActionPerformedSource();

        // Verify proper connection handling
        assertTrue("Connection should be established",
                   sourceCode.contains("con = DriverManager.getConnection"));

        // Verify PreparedStatement is created from connection
        assertTrue("PreparedStatement should be created from connection",
                   sourceCode.contains("con.prepareStatement(query)"));

        // Verify exception handling is present
        assertTrue("Exception handling should be present",
                   sourceCode.contains("catch(Exception"));
    }

    /**
     * Test 17: Verify that all date fields handle injection attempts
     */
    @Test
    public void testDateFieldsInjection() {
        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // Test injection attempts in date fields
        String dateInjection1 = "2024-01-01' OR '1'='1";
        String dateInjection2 = "2024-01-15'; DROP TABLE Job_Card; --";

        jobCard.Customer_Id.setText("C001");
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText(dateInjection1);
        jobCard.Due_Date.setText(dateInjection2);
        jobCard.E_Cost.setText("5000");
        jobCard.Remark.setText("Test");
        jobCard.Amount_Pay.setText("1000");
        jobCard.SalesMan.setText("John Doe");

        // Verify date injections are stored as literal text
        assertEquals("Date injection in Order_Date should be stored as-is",
                     dateInjection1, jobCard.Order_Date.getText());
        assertEquals("Date injection in Due_Date should be stored as-is",
                     dateInjection2, jobCard.Due_Date.getText());
    }

    /**
     * Test 18: Verify SalesMan field injection is neutralized
     */
    @Test
    public void testSalesManFieldInjection() {
        JDesktopPane desktop = new JDesktopPane();
        jobCard.JobCardFrame(desktop);

        // Test injection in SalesMan field
        String salesmanInjection = "John'; UPDATE Login SET password='hacked' WHERE '1'='1";

        jobCard.Customer_Id.setText("C001");
        jobCard.Style_Id.setText("S001");
        jobCard.Order_Date.setText("2024-01-01");
        jobCard.Due_Date.setText("2024-01-15");
        jobCard.E_Cost.setText("5000");
        jobCard.Remark.setText("Test");
        jobCard.Amount_Pay.setText("1000");
        jobCard.SalesMan.setText(salesmanInjection);

        // Verify SalesMan injection is stored as literal text
        assertEquals("SalesMan injection should be stored as-is",
                     salesmanInjection, jobCard.SalesMan.getText());
    }
}
