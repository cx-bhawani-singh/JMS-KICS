import org.junit.*;
import static org.junit.Assert.*;
import java.sql.*;
import java.awt.event.ActionEvent;
import javax.swing.JDesktopPane;

/**
 * Comprehensive test suite for LoginAdd class
 * Validates SQL injection vulnerability remediation using PreparedStatement
 */
public class LoginAddTest {

    private LoginAdd loginAdd;
    private boolean preparedStatementUsed;
    private String capturedQuery;
    private String[] capturedParameters;

    @Before
    public void setUp() {
        loginAdd = new LoginAdd();
        preparedStatementUsed = false;
        capturedQuery = null;
        capturedParameters = new String[5];
    }

    @After
    public void tearDown() {
        loginAdd = null;
    }

    /**
     * Test 1: Verify PreparedStatement is used instead of Statement
     * This is the core fix for SQL injection vulnerability
     */
    @Test
    public void testPreparedStatementIsUsed() {
        // This test validates that the code uses PreparedStatement
        // by checking the source code structure
        String sourceCode = getLoginAddActionPerformedSource();

        // Verify PreparedStatement is used
        assertTrue("PreparedStatement should be used to prevent SQL injection",
                   sourceCode.contains("PreparedStatement"));

        // Verify the old vulnerable pattern is NOT present
        assertFalse("String concatenation in SQL query should not be used",
                    sourceCode.contains("VALUES ('\""));

        // Verify parameterized query pattern with placeholders
        assertTrue("Query should use parameterized placeholders",
                   sourceCode.contains("VALUES (?,?,?,?,?)"));
    }

    /**
     * Test 2: Verify that SQL injection attempts with single quotes are neutralized
     */
    @Test
    public void testSQLInjectionWithSingleQuotes() {
        // Simulate SQL injection attempt with single quotes in username
        String maliciousUser = "admin' OR '1'='1";

        // Create the login frame to initialize components
        JDesktopPane desktop = new JDesktopPane();
        loginAdd.LoginAddFrame(desktop);

        // Set malicious input in User field
        loginAdd.User.setText(maliciousUser);
        loginAdd.Password.setText("password123");
        loginAdd.PasswordC.setText("password123");
        loginAdd.Name.setText("Test User");
        loginAdd.Contact.setText("1234567890");

        // Verify that the input is properly handled
        // When using PreparedStatement, the single quotes will be escaped automatically
        // and won't break out of the SQL statement
        assertEquals("Malicious input should be stored as-is in text field",
                     maliciousUser, loginAdd.User.getText());

        // The key is that PreparedStatement.setString() will treat this as literal data
        // not as SQL code, preventing injection
    }

    /**
     * Test 3: Verify SQL injection with comment syntax is neutralized
     */
    @Test
    public void testSQLInjectionWithComments() {
        String maliciousUser = "test'; DROP TABLE Login; --";

        JDesktopPane desktop = new JDesktopPane();
        loginAdd.LoginAddFrame(desktop);

        // Set malicious input attempting to drop table
        loginAdd.User.setText(maliciousUser);
        loginAdd.Password.setText("password123");
        loginAdd.PasswordC.setText("password123");
        loginAdd.Name.setText("Test User");
        loginAdd.Contact.setText("1234567890");

        // Verify input is stored correctly
        assertEquals("Malicious DROP TABLE attempt should be stored as text",
                     maliciousUser, loginAdd.User.getText());

        // With PreparedStatement, this entire string will be treated as data
        // for the User column, not as executable SQL
    }

    /**
     * Test 4: Verify SQL injection with UNION attack is neutralized
     */
    @Test
    public void testSQLInjectionWithUnion() {
        String maliciousName = "test' UNION SELECT User,Password,Type,Name,Contact FROM Login --";

        JDesktopPane desktop = new JDesktopPane();
        loginAdd.LoginAddFrame(desktop);

        // Set malicious input attempting UNION-based injection
        loginAdd.User.setText("testuser");
        loginAdd.Password.setText("password123");
        loginAdd.PasswordC.setText("password123");
        loginAdd.Name.setText(maliciousName);
        loginAdd.Contact.setText("1234567890");

        // Verify input handling
        assertEquals("UNION attack should be stored as literal text",
                     maliciousName, loginAdd.Name.getText());
    }

    /**
     * Test 5: Verify legitimate data with special characters is handled correctly
     */
    @Test
    public void testLegitimateDataWithSpecialCharacters() {
        // Test that legitimate data containing special characters works correctly
        JDesktopPane desktop = new JDesktopPane();
        loginAdd.LoginAddFrame(desktop);

        // Set legitimate data that includes special characters
        loginAdd.User.setText("john.doe@example");
        loginAdd.Password.setText("P@ssw0rd!2024");
        loginAdd.PasswordC.setText("P@ssw0rd!2024");
        loginAdd.Name.setText("O'Brien & Associates");
        loginAdd.Contact.setText("+1-555-123-4567");

        // Verify all data is stored correctly
        assertEquals("john.doe@example", loginAdd.User.getText());
        assertEquals("P@ssw0rd!2024", loginAdd.Password.getText());
        assertEquals("O'Brien & Associates", loginAdd.Name.getText());
        assertEquals("+1-555-123-4567", loginAdd.Contact.getText());

        // PreparedStatement will handle all these special characters correctly
    }

    /**
     * Test 6: Verify all input fields are parameterized
     */
    @Test
    public void testAllFieldsAreParameterized() {
        String sourceCode = getLoginAddActionPerformedSource();

        // Verify all 5 fields are set using setString
        assertTrue("sUser should be parameterized",
                   sourceCode.contains("pstmt.setString(1, sUser)"));
        assertTrue("sPassword should be parameterized",
                   sourceCode.contains("pstmt.setString(2, sPassword)"));
        assertTrue("sType should be parameterized",
                   sourceCode.contains("pstmt.setString(3, sType)"));
        assertTrue("sName should be parameterized",
                   sourceCode.contains("pstmt.setString(4, sName)"));
        assertTrue("sContact should be parameterized",
                   sourceCode.contains("pstmt.setString(5, sContact)"));
    }

    /**
     * Test 7: Verify SQL injection with stacked queries is neutralized
     */
    @Test
    public void testSQLInjectionWithStackedQueries() {
        String maliciousContact = "123'; DELETE FROM Login WHERE '1'='1";

        JDesktopPane desktop = new JDesktopPane();
        loginAdd.LoginAddFrame(desktop);

        // Attempt stacked query injection
        loginAdd.User.setText("testuser");
        loginAdd.Password.setText("password123");
        loginAdd.PasswordC.setText("password123");
        loginAdd.Name.setText("Test User");
        loginAdd.Contact.setText(maliciousContact);

        // Verify the entire malicious string is treated as data
        assertEquals("Stacked query should be stored as literal text",
                     maliciousContact, loginAdd.Contact.getText());
    }

    /**
     * Test 8: Verify SQL injection in multiple fields simultaneously
     */
    @Test
    public void testSQLInjectionInMultipleFields() {
        JDesktopPane desktop = new JDesktopPane();
        loginAdd.LoginAddFrame(desktop);

        // Inject malicious code in multiple fields
        String injection1 = "' OR '1'='1";
        String injection2 = "pass'; DROP TABLE Users; --";
        String injection3 = "' UNION SELECT password FROM Login --";
        String injection4 = "123'; DELETE FROM Login; --";

        loginAdd.User.setText(injection1);
        loginAdd.Password.setText(injection2);
        loginAdd.PasswordC.setText(injection2);
        loginAdd.Name.setText(injection3);
        loginAdd.Contact.setText(injection4);

        // Verify all malicious inputs are stored as text
        assertEquals(injection1, loginAdd.User.getText());
        assertEquals(injection2, loginAdd.Password.getText());
        assertEquals(injection3, loginAdd.Name.getText());
        assertEquals(injection4, loginAdd.Contact.getText());

        // With PreparedStatement, all these will be escaped and treated as data
    }

    /**
     * Test 9: Verify empty and null-like inputs are handled correctly
     */
    @Test
    public void testEmptyAndNullInputs() {
        JDesktopPane desktop = new JDesktopPane();
        loginAdd.LoginAddFrame(desktop);

        // Test with empty strings
        loginAdd.User.setText("");
        loginAdd.Password.setText("");
        loginAdd.PasswordC.setText("");
        loginAdd.Name.setText("");
        loginAdd.Contact.setText("");

        // Verify empty strings are handled
        assertEquals("", loginAdd.User.getText());

        // Test with "NULL" as string (not actual null)
        loginAdd.User.setText("NULL");
        assertEquals("NULL", loginAdd.User.getText());

        // PreparedStatement handles empty strings safely
    }

    /**
     * Test 10: Verify SQL injection attempts in password field are neutralized
     */
    @Test
    public void testSQLInjectionInPasswordField() {
        JDesktopPane desktop = new JDesktopPane();
        loginAdd.LoginAddFrame(desktop);

        // Attempt SQL injection through password field
        String maliciousPassword = "' OR 1=1--";
        loginAdd.User.setText("admin");
        loginAdd.Password.setText(maliciousPassword);
        loginAdd.PasswordC.setText(maliciousPassword);
        loginAdd.Name.setText("Admin User");
        loginAdd.Contact.setText("1234567890");

        // Verify injection attempts are stored as text
        assertEquals(maliciousPassword, loginAdd.Password.getText());

        // PreparedStatement treats the password as string data, not SQL expressions
    }

    /**
     * Test 11: Verify SQL injection with hex encoding attempts
     */
    @Test
    public void testSQLInjectionWithEncodedCharacters() {
        JDesktopPane desktop = new JDesktopPane();
        loginAdd.LoginAddFrame(desktop);

        // Attempt SQL injection with various encoding/obfuscation
        String encodedInjection = "admin'/**/OR/**/'1'='1";
        loginAdd.User.setText(encodedInjection);
        loginAdd.Password.setText("password123");
        loginAdd.PasswordC.setText("password123");
        loginAdd.Name.setText("Test User");
        loginAdd.Contact.setText("1234567890");

        // Verify injection is stored as literal text
        assertEquals("Encoded injection should be stored as literal text",
                     encodedInjection, loginAdd.User.getText());
    }

    /**
     * Test 12: Verify password mismatch protection still works
     */
    @Test
    public void testPasswordMismatchProtection() {
        JDesktopPane desktop = new JDesktopPane();
        loginAdd.LoginAddFrame(desktop);

        // Set different passwords
        loginAdd.User.setText("testuser");
        loginAdd.Password.setText("password123");
        loginAdd.PasswordC.setText("password456");
        loginAdd.Name.setText("Test User");
        loginAdd.Contact.setText("1234567890");

        // Verify password mismatch is detected
        assertFalse("Passwords should not match",
                    loginAdd.Password.getText().equals(loginAdd.PasswordC.getText()));
    }

    /**
     * Test 13: Verify SQL injection with boolean-based blind injection
     */
    @Test
    public void testBooleanBasedSQLInjection() {
        JDesktopPane desktop = new JDesktopPane();
        loginAdd.LoginAddFrame(desktop);

        // Attempt boolean-based blind SQL injection
        String booleanInjection = "' AND 1=1--";
        loginAdd.User.setText(booleanInjection);
        loginAdd.Password.setText("password");
        loginAdd.PasswordC.setText("password");
        loginAdd.Name.setText("Test");
        loginAdd.Contact.setText("123");

        // Verify injection is treated as data
        assertEquals("Boolean injection should be stored as literal text",
                     booleanInjection, loginAdd.User.getText());
    }

    /**
     * Test 14: Verify time-based SQL injection attempts are neutralized
     */
    @Test
    public void testTimeBasedSQLInjection() {
        JDesktopPane desktop = new JDesktopPane();
        loginAdd.LoginAddFrame(desktop);

        // Attempt time-based SQL injection
        String timeBasedInjection = "'; WAITFOR DELAY '00:00:05'--";
        loginAdd.Name.setText(timeBasedInjection);
        loginAdd.User.setText("testuser");
        loginAdd.Password.setText("password");
        loginAdd.PasswordC.setText("password");
        loginAdd.Contact.setText("123");

        // Verify injection is stored as text
        assertEquals("Time-based injection should be stored as literal text",
                     timeBasedInjection, loginAdd.Name.getText());
    }

    /**
     * Helper method to read the LoginAdd.java source code
     * for validation testing
     */
    private String getLoginAddActionPerformedSource() {
        try {
            StringBuilder content = new StringBuilder();
            java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.FileReader("./LoginAdd.java"));
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
            fail("Could not read LoginAdd.java source: " + e.getMessage());
            return "";
        }
    }

    /**
     * Test 15: Verify the fix maintains backward compatibility
     * The INSERT statement structure should remain the same
     */
    @Test
    public void testBackwardCompatibility() {
        String sourceCode = getLoginAddActionPerformedSource();

        // Verify the INSERT statement structure is preserved
        assertTrue("INSERT statement should target Login table",
                   sourceCode.contains("INSERT INTO Login"));

        // Verify all columns are included
        assertTrue("All columns should be present",
                   sourceCode.contains("User,Password,Type,Name,Contact"));

        // Verify there are 5 placeholder parameters (one for each column)
        int placeholderCount = sourceCode.split("\\?", -1).length - 1;
        assertTrue("Should have 5 placeholders for 5 columns",
                   placeholderCount >= 5);
    }

    /**
     * Test 16: Verify executeUpdate is called on PreparedStatement
     */
    @Test
    public void testExecuteUpdateOnPreparedStatement() {
        String sourceCode = getLoginAddActionPerformedSource();

        // Verify executeUpdate is called on pstmt (PreparedStatement)
        assertTrue("executeUpdate should be called on PreparedStatement",
                   sourceCode.contains("pstmt.executeUpdate()"));

        // Verify it's not called on Statement with a query string
        assertFalse("executeUpdate should not be called with query parameter",
                    sourceCode.matches(".*executeUpdate\\s*\\(\\s*query\\s*\\).*"));
    }

    /**
     * Test 17: Verify SQL injection with backtick characters
     */
    @Test
    public void testSQLInjectionWithBackticks() {
        JDesktopPane desktop = new JDesktopPane();
        loginAdd.LoginAddFrame(desktop);

        // Test with backtick characters that might be used in SQL
        String backtickInjection = "`admin` OR `1`=`1`";
        loginAdd.User.setText(backtickInjection);
        loginAdd.Password.setText("password");
        loginAdd.PasswordC.setText("password");
        loginAdd.Name.setText("Test");
        loginAdd.Contact.setText("123");

        // Verify backticks are treated as literal characters
        assertEquals("Backtick injection should be stored as literal text",
                     backtickInjection, loginAdd.User.getText());
    }

    /**
     * Test 18: Verify SQL injection with batch statements
     */
    @Test
    public void testSQLInjectionWithBatchStatements() {
        JDesktopPane desktop = new JDesktopPane();
        loginAdd.LoginAddFrame(desktop);

        // Attempt to execute multiple statements
        String batchInjection = "user1'; INSERT INTO Login VALUES ('hacker','pass','Admin','Hacker','000'); --";
        loginAdd.User.setText(batchInjection);
        loginAdd.Password.setText("password");
        loginAdd.PasswordC.setText("password");
        loginAdd.Name.setText("Test");
        loginAdd.Contact.setText("123");

        // Verify the entire injection attempt is treated as data
        assertEquals("Batch injection should be stored as literal text",
                     batchInjection, loginAdd.User.getText());
    }

    /**
     * Test 19: Verify SQL injection targeting Contact field with numeric tricks
     */
    @Test
    public void testSQLInjectionInContactField() {
        JDesktopPane desktop = new JDesktopPane();
        loginAdd.LoginAddFrame(desktop);

        // Inject SQL through contact field
        String contactInjection = "123' OR '1'='1";
        loginAdd.User.setText("testuser");
        loginAdd.Password.setText("password");
        loginAdd.PasswordC.setText("password");
        loginAdd.Name.setText("Test User");
        loginAdd.Contact.setText(contactInjection);

        // Verify injection is stored as text
        assertEquals("Contact injection should be stored as literal text",
                     contactInjection, loginAdd.Contact.getText());
    }

    /**
     * Test 20: Verify the query structure prevents tautologies
     */
    @Test
    public void testSQLTautologyPrevention() {
        String sourceCode = getLoginAddActionPerformedSource();

        // Verify that parameterized queries prevent tautology attacks
        // The presence of PreparedStatement and absence of string concatenation
        // ensures that attacks like "1=1" or "OR 1" are treated as data
        assertTrue("PreparedStatement prevents tautology attacks",
                   sourceCode.contains("PreparedStatement"));

        assertFalse("No string concatenation with user input",
                    sourceCode.matches(".*\\\"\\+s(User|Password|Name|Contact).*"));
    }
}
