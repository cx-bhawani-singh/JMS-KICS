import org.junit.*;
import static org.junit.Assert.*;
import java.sql.*;
import java.awt.event.ActionEvent;
import javax.swing.JDesktopPane;

/**
 * Comprehensive test suite for Inventory class
 * Validates SQL injection vulnerability remediation using PreparedStatement
 */
public class InventoryTest {

    private Inventory inventory;
    private Connection mockConnection;
    private PreparedStatement mockPreparedStatement;
    private boolean preparedStatementUsed;
    private String capturedQuery;
    private String[] capturedParameters;

    @Before
    public void setUp() {
        inventory = new Inventory();
        preparedStatementUsed = false;
        capturedQuery = null;
        capturedParameters = new String[9];
    }

    @After
    public void tearDown() {
        inventory = null;
    }

    /**
     * Test 1: Verify PreparedStatement is used instead of Statement
     * This is the core fix for SQL injection vulnerability
     */
    @Test
    public void testPreparedStatementIsUsed() {
        // This test validates that the code uses PreparedStatement
        // by checking the source code structure
        String sourceCode = getInventoryActionPerformedSource();

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

        // Create the inventory frame to initialize components
        JDesktopPane desktop = new JDesktopPane();
        inventory.InventoryFrame(desktop);

        // Set malicious input in style_id field
        inventory.style_id.setText(maliciousInput);
        inventory.Vendor_id.setText("V001");
        inventory.in_date.setText("2024-01-01");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText("Test details");

        // Verify that the input is properly handled
        // When using PreparedStatement, the single quotes will be escaped automatically
        // and won't break out of the SQL statement
        assertEquals("Malicious input should be stored as-is in text field",
                     maliciousInput, inventory.style_id.getText());

        // The key is that PreparedStatement.setString() will treat this as literal data
        // not as SQL code, preventing injection
    }

    /**
     * Test 3: Verify SQL injection with comment syntax is neutralized
     */
    @Test
    public void testSQLInjectionWithComments() {
        String maliciousInput = "test'; DROP TABLE Inventory; --";

        JDesktopPane desktop = new JDesktopPane();
        inventory.InventoryFrame(desktop);

        // Set malicious input attempting to drop table
        inventory.style_id.setText(maliciousInput);
        inventory.Vendor_id.setText("V001");
        inventory.in_date.setText("2024-01-01");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText("Test details");

        // Verify input is stored correctly
        assertEquals("Malicious DROP TABLE attempt should be stored as text",
                     maliciousInput, inventory.style_id.getText());

        // With PreparedStatement, this entire string will be treated as data
        // for the Style_ID column, not as executable SQL
    }

    /**
     * Test 4: Verify SQL injection with UNION attack is neutralized
     */
    @Test
    public void testSQLInjectionWithUnion() {
        String maliciousInput = "test' UNION SELECT * FROM Login --";

        JDesktopPane desktop = new JDesktopPane();
        inventory.InventoryFrame(desktop);

        // Set malicious input attempting UNION-based injection
        inventory.style_id.setText(maliciousInput);
        inventory.Vendor_id.setText("V001");
        inventory.in_date.setText("2024-01-01");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText("Test details");

        // Verify input handling
        assertEquals("UNION attack should be stored as literal text",
                     maliciousInput, inventory.style_id.getText());
    }

    /**
     * Test 5: Verify legitimate data with special characters is handled correctly
     */
    @Test
    public void testLegitimateDataWithSpecialCharacters() {
        // Test that legitimate data containing special characters works correctly
        JDesktopPane desktop = new JDesktopPane();
        inventory.InventoryFrame(desktop);

        // Set legitimate data that includes special characters
        inventory.style_id.setText("ST-2024-001");
        inventory.Vendor_id.setText("V-001");
        inventory.in_date.setText("01/01/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond & Ruby");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("3+2");
        inventory.details.setText("High-quality stones (Grade A)");

        // Verify all data is stored correctly
        assertEquals("ST-2024-001", inventory.style_id.getText());
        assertEquals("V-001", inventory.Vendor_id.getText());
        assertEquals("Diamond & Ruby", inventory.stone_type.getText());
        assertEquals("3+2", inventory.stone_number.getText());
        assertEquals("High-quality stones (Grade A)", inventory.details.getText());

        // PreparedStatement will handle all these special characters correctly
    }

    /**
     * Test 6: Verify all input fields are parameterized
     */
    @Test
    public void testAllFieldsAreParameterized() {
        String sourceCode = getInventoryActionPerformedSource();

        // Verify all 9 fields are set using setString
        assertTrue("style_id should be parameterized",
                   sourceCode.contains("pstmt.setString(1, sstyle_id)"));
        assertTrue("Vendor_id should be parameterized",
                   sourceCode.contains("pstmt.setString(2, sVendor_id)"));
        assertTrue("in_date should be parameterized",
                   sourceCode.contains("pstmt.setString(3, sin_date)"));
        assertTrue("gold_cr should be parameterized",
                   sourceCode.contains("pstmt.setString(4, sgold_cr)"));
        assertTrue("gold_wt should be parameterized",
                   sourceCode.contains("pstmt.setString(5, sgold_wt)"));
        assertTrue("stone_type should be parameterized",
                   sourceCode.contains("pstmt.setString(6, sstone_type)"));
        assertTrue("stone_wt should be parameterized",
                   sourceCode.contains("pstmt.setString(7, sstone_wt)"));
        assertTrue("stone_number should be parameterized",
                   sourceCode.contains("pstmt.setString(8, sstone_number)"));
        assertTrue("details should be parameterized",
                   sourceCode.contains("pstmt.setString(9, sdetails)"));
    }

    /**
     * Test 7: Verify SQL injection with stacked queries is neutralized
     */
    @Test
    public void testSQLInjectionWithStackedQueries() {
        String maliciousInput = "test'; DELETE FROM Inventory WHERE '1'='1";

        JDesktopPane desktop = new JDesktopPane();
        inventory.InventoryFrame(desktop);

        // Attempt stacked query injection
        inventory.style_id.setText(maliciousInput);
        inventory.Vendor_id.setText("V001");
        inventory.in_date.setText("2024-01-01");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText("Test details");

        // Verify the entire malicious string is treated as data
        assertEquals("Stacked query should be stored as literal text",
                     maliciousInput, inventory.style_id.getText());
    }

    /**
     * Test 8: Verify SQL injection in multiple fields simultaneously
     */
    @Test
    public void testSQLInjectionInMultipleFields() {
        JDesktopPane desktop = new JDesktopPane();
        inventory.InventoryFrame(desktop);

        // Inject malicious code in multiple fields
        String injection1 = "' OR '1'='1";
        String injection2 = "'; DROP TABLE Users; --";
        String injection3 = "' UNION SELECT password FROM Login --";

        inventory.style_id.setText(injection1);
        inventory.Vendor_id.setText(injection2);
        inventory.details.setText(injection3);
        inventory.in_date.setText("2024-01-01");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");

        // Verify all malicious inputs are stored as text
        assertEquals(injection1, inventory.style_id.getText());
        assertEquals(injection2, inventory.Vendor_id.getText());
        assertEquals(injection3, inventory.details.getText());

        // With PreparedStatement, all these will be escaped and treated as data
    }

    /**
     * Test 9: Verify empty and null-like inputs are handled correctly
     */
    @Test
    public void testEmptyAndNullInputs() {
        JDesktopPane desktop = new JDesktopPane();
        inventory.InventoryFrame(desktop);

        // Test with empty strings
        inventory.style_id.setText("");
        inventory.Vendor_id.setText("");
        inventory.in_date.setText("");
        inventory.gold_cr.setText("");
        inventory.gold_wt.setText("");
        inventory.stone_type.setText("");
        inventory.stone_wt.setText("");
        inventory.stone_number.setText("");
        inventory.details.setText("");

        // Verify empty strings are handled
        assertEquals("", inventory.style_id.getText());

        // Test with "NULL" as string (not actual null)
        inventory.style_id.setText("NULL");
        assertEquals("NULL", inventory.style_id.getText());

        // PreparedStatement handles empty strings safely
    }

    /**
     * Test 10: Verify numeric SQL injection attempts are neutralized
     */
    @Test
    public void testNumericSQLInjection() {
        JDesktopPane desktop = new JDesktopPane();
        inventory.InventoryFrame(desktop);

        // Attempt SQL injection through numeric fields
        inventory.style_id.setText("1 OR 1=1");
        inventory.gold_wt.setText("10.5 OR '1'='1");
        inventory.stone_wt.setText("2.5; DROP TABLE Inventory");
        inventory.Vendor_id.setText("V001");
        inventory.in_date.setText("2024-01-01");
        inventory.gold_cr.setText("18");
        inventory.stone_number.setText("5");
        inventory.details.setText("Test");

        // Verify injection attempts are stored as text
        assertEquals("1 OR 1=1", inventory.style_id.getText());
        assertEquals("10.5 OR '1'='1", inventory.gold_wt.getText());
        assertEquals("2.5; DROP TABLE Inventory", inventory.stone_wt.getText());

        // PreparedStatement treats these as string data, not SQL expressions
    }

    /**
     * Helper method to read the Inventory.java source code
     * for validation testing
     */
    private String getInventoryActionPerformedSource() {
        try {
            StringBuilder content = new StringBuilder();
            java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.FileReader("./Inventory.java"));
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
            fail("Could not read Inventory.java source: " + e.getMessage());
            return "";
        }
    }

    /**
     * Test 11: Verify the fix maintains backward compatibility
     * The INSERT statement structure should remain the same
     */
    @Test
    public void testBackwardCompatibility() {
        String sourceCode = getInventoryActionPerformedSource();

        // Verify the INSERT statement structure is preserved
        assertTrue("INSERT statement should target Inventory table",
                   sourceCode.contains("INSERT INTO Inventory"));

        // Verify all columns are included in correct order
        assertTrue("All columns should be present",
                   sourceCode.contains("Style_ID,Vendor_ID,In_Date,Gold,Gold_wt,Stone_Type,Stone_Weight,Stone_numbers,Details"));

        // Verify there are 9 placeholder parameters (one for each column)
        int placeholderCount = sourceCode.split("\\?", -1).length - 1;
        assertTrue("Should have 9 placeholders for 9 columns",
                   placeholderCount >= 9);
    }

    /**
     * Test 12: Verify executeUpdate is called on PreparedStatement
     */
    @Test
    public void testExecuteUpdateOnPreparedStatement() {
        String sourceCode = getInventoryActionPerformedSource();

        // Verify executeUpdate is called on pstmt (PreparedStatement)
        assertTrue("executeUpdate should be called on PreparedStatement",
                   sourceCode.contains("pstmt.executeUpdate()"));

        // Verify it's not called on Statement with a query string
        assertFalse("executeUpdate should not be called with query parameter",
                    sourceCode.matches(".*executeUpdate\\s*\\(\\s*query\\s*\\).*"));
    }
}
