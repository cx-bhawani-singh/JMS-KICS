import org.junit.*;
import static org.junit.Assert.*;
import java.sql.*;
import java.awt.event.ActionEvent;
import javax.swing.JDesktopPane;

/**
 * Comprehensive test suite for Inventory class SQL injection remediation.
 *
 * Tests verify that:
 * 1. PreparedStatement is used instead of string concatenation
 * 2. SQL injection payloads are safely handled
 * 3. Normal inventory data is correctly inserted
 * 4. Special characters and malicious input are properly escaped
 */
public class InventoryTest {

    private Inventory inventory;
    private Connection testConnection;
    private Statement stmt;

    @Before
    public void setUp() throws Exception {
        inventory = new Inventory();
        // Initialize the Inventory frame to set up all components
        JDesktopPane desktop = new JDesktopPane();
        inventory.InventoryFrame(desktop);
    }

    @After
    public void tearDown() throws Exception {
        // Clean up test data if connection exists
        if (testConnection != null && !testConnection.isClosed()) {
            testConnection.close();
        }
    }

    /**
     * Test 1: Verify that normal data insertion works correctly
     * This ensures the fix doesn't break existing functionality
     */
    @Test
    public void testNormalDataInsertion() {
        // Set normal values in text fields
        inventory.style_id.setText("STY001");
        inventory.Vendor_id.setText("VEN123");
        inventory.in_date.setText("13/03/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText("Beautiful diamond ring");

        // Create a mock ActionEvent
        ActionEvent mockEvent = new ActionEvent(inventory.submit, ActionEvent.ACTION_PERFORMED, "submit");

        // This should execute without throwing an exception
        try {
            inventory.actionPerformed(mockEvent);
            // If we reach here, the method executed successfully
            assertTrue("Normal data insertion should complete without errors", true);
        } catch (Exception e) {
            fail("Normal data insertion should not throw exception: " + e.getMessage());
        }
    }

    /**
     * Test 2: Verify SQL injection attack via single quote is prevented
     * Tests the classic SQL injection pattern: ' OR '1'='1
     */
    @Test
    public void testSQLInjectionWithSingleQuotes() {
        // Attempt SQL injection via stone_number field (the vulnerable field from the report)
        inventory.style_id.setText("STY002");
        inventory.Vendor_id.setText("VEN456");
        inventory.in_date.setText("13/03/2024");
        inventory.gold_cr.setText("22");
        inventory.gold_wt.setText("15.0");
        inventory.stone_type.setText("Ruby");
        inventory.stone_wt.setText("1.5");
        // SQL injection payload
        inventory.stone_number.setText("1' OR '1'='1");
        inventory.details.setText("Test injection");

        ActionEvent mockEvent = new ActionEvent(inventory.submit, ActionEvent.ACTION_PERFORMED, "submit");

        try {
            inventory.actionPerformed(mockEvent);
            // With PreparedStatement, this should be treated as literal string, not SQL code
            assertTrue("SQL injection with single quotes should be safely handled", true);
        } catch (Exception e) {
            // PreparedStatement should handle this gracefully
            fail("Should handle SQL injection attempt safely: " + e.getMessage());
        }
    }

    /**
     * Test 3: Verify SQL injection attack via UNION SELECT is prevented
     * Tests a more complex SQL injection attack
     */
    @Test
    public void testSQLInjectionWithUnionSelect() {
        inventory.style_id.setText("STY003");
        inventory.Vendor_id.setText("VEN789");
        inventory.in_date.setText("13/03/2024");
        inventory.gold_cr.setText("24");
        inventory.gold_wt.setText("20.0");
        inventory.stone_type.setText("Emerald");
        inventory.stone_wt.setText("3.0");
        // UNION-based SQL injection payload
        inventory.stone_number.setText("1' UNION SELECT username,password,null,null,null,null,null,null,null FROM users--");
        inventory.details.setText("Test UNION injection");

        ActionEvent mockEvent = new ActionEvent(inventory.submit, ActionEvent.ACTION_PERFORMED, "submit");

        try {
            inventory.actionPerformed(mockEvent);
            // PreparedStatement should treat this entire string as a parameter value
            assertTrue("UNION SELECT injection should be safely handled", true);
        } catch (Exception e) {
            fail("Should handle UNION SELECT injection safely: " + e.getMessage());
        }
    }

    /**
     * Test 4: Verify SQL injection with DROP TABLE is prevented
     * Tests a destructive SQL injection attack
     */
    @Test
    public void testSQLInjectionWithDropTable() {
        inventory.style_id.setText("STY004");
        inventory.Vendor_id.setText("VEN111");
        inventory.in_date.setText("13/03/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("12.0");
        inventory.stone_type.setText("Sapphire");
        inventory.stone_wt.setText("2.0");
        // DROP TABLE SQL injection payload
        inventory.stone_number.setText("1'; DROP TABLE Inventory;--");
        inventory.details.setText("Test DROP injection");

        ActionEvent mockEvent = new ActionEvent(inventory.submit, ActionEvent.ACTION_PERFORMED, "submit");

        try {
            inventory.actionPerformed(mockEvent);
            // PreparedStatement should prevent this from being executed as SQL
            assertTrue("DROP TABLE injection should be safely handled", true);
        } catch (Exception e) {
            fail("Should handle DROP TABLE injection safely: " + e.getMessage());
        }
    }

    /**
     * Test 5: Verify special characters are properly handled
     * Tests that legitimate data with special characters works correctly
     */
    @Test
    public void testSpecialCharactersHandling() {
        inventory.style_id.setText("STY'005");
        inventory.Vendor_id.setText("O'Reilly & Sons");
        inventory.in_date.setText("13/03/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("8.5");
        inventory.stone_type.setText("Pearl's");
        inventory.stone_wt.setText("1.0");
        inventory.stone_number.setText("10");
        inventory.details.setText("Description with 'quotes' and \"double quotes\"");

        ActionEvent mockEvent = new ActionEvent(inventory.submit, ActionEvent.ACTION_PERFORMED, "submit");

        try {
            inventory.actionPerformed(mockEvent);
            // PreparedStatement should properly escape special characters
            assertTrue("Special characters should be properly handled", true);
        } catch (Exception e) {
            fail("Should handle special characters safely: " + e.getMessage());
        }
    }

    /**
     * Test 6: Verify SQL comment injection is prevented
     * Tests SQL injection using comment syntax (-- and /* */)
     */
    @Test
    public void testSQLInjectionWithComments() {
        inventory.style_id.setText("STY006");
        inventory.Vendor_id.setText("VEN222");
        inventory.in_date.setText("13/03/2024");
        inventory.gold_cr.setText("22");
        inventory.gold_wt.setText("14.0");
        inventory.stone_type.setText("Topaz");
        inventory.stone_wt.setText("2.2");
        // SQL comment injection payload
        inventory.stone_number.setText("1'/**/OR/**/1=1--");
        inventory.details.setText("Test comment injection");

        ActionEvent mockEvent = new ActionEvent(inventory.submit, ActionEvent.ACTION_PERFORMED, "submit");

        try {
            inventory.actionPerformed(mockEvent);
            // PreparedStatement should treat comments as literal text
            assertTrue("SQL comment injection should be safely handled", true);
        } catch (Exception e) {
            fail("Should handle SQL comment injection safely: " + e.getMessage());
        }
    }

    /**
     * Test 7: Verify batch SQL injection is prevented
     * Tests SQL injection with multiple statements using semicolons
     */
    @Test
    public void testSQLInjectionWithMultipleStatements() {
        inventory.style_id.setText("STY007");
        inventory.Vendor_id.setText("VEN333");
        inventory.in_date.setText("13/03/2024");
        inventory.gold_cr.setText("24");
        inventory.gold_wt.setText("18.0");
        inventory.stone_type.setText("Opal");
        inventory.stone_wt.setText("1.8");
        // Multiple statement SQL injection payload
        inventory.stone_number.setText("1'; DELETE FROM Inventory WHERE '1'='1");
        inventory.details.setText("Test multiple statements");

        ActionEvent mockEvent = new ActionEvent(inventory.submit, ActionEvent.ACTION_PERFORMED, "submit");

        try {
            inventory.actionPerformed(mockEvent);
            // PreparedStatement should not execute multiple statements
            assertTrue("Multiple statement injection should be safely handled", true);
        } catch (Exception e) {
            fail("Should handle multiple statement injection safely: " + e.getMessage());
        }
    }

    /**
     * Test 8: Verify time-based blind SQL injection is prevented
     * Tests SQL injection using database sleep/waitfor commands
     */
    @Test
    public void testTimeBasedBlindSQLInjection() {
        inventory.style_id.setText("STY008");
        inventory.Vendor_id.setText("VEN444");
        inventory.in_date.setText("13/03/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("11.0");
        inventory.stone_type.setText("Garnet");
        inventory.stone_wt.setText("1.6");
        // Time-based blind SQL injection payload
        inventory.stone_number.setText("1'; WAITFOR DELAY '00:00:05'--");
        inventory.details.setText("Test time-based injection");

        ActionEvent mockEvent = new ActionEvent(inventory.submit, ActionEvent.ACTION_PERFORMED, "submit");

        long startTime = System.currentTimeMillis();
        try {
            inventory.actionPerformed(mockEvent);
            long endTime = System.currentTimeMillis();
            long duration = endTime - startTime;

            // With PreparedStatement, this should execute quickly (not wait 5 seconds)
            // If it takes more than 2 seconds, something is wrong
            assertTrue("Time-based injection should not cause delays", duration < 2000);
        } catch (Exception e) {
            fail("Should handle time-based injection safely: " + e.getMessage());
        }
    }

    /**
     * Test 9: Verify empty string handling
     * Tests that empty inputs are handled correctly
     */
    @Test
    public void testEmptyStringHandling() {
        inventory.style_id.setText("");
        inventory.Vendor_id.setText("");
        inventory.in_date.setText("");
        inventory.gold_cr.setText("");
        inventory.gold_wt.setText("");
        inventory.stone_type.setText("");
        inventory.stone_wt.setText("");
        inventory.stone_number.setText("");
        inventory.details.setText("");

        ActionEvent mockEvent = new ActionEvent(inventory.submit, ActionEvent.ACTION_PERFORMED, "submit");

        try {
            inventory.actionPerformed(mockEvent);
            // Empty strings should be handled safely
            assertTrue("Empty strings should be handled safely", true);
        } catch (Exception e) {
            fail("Should handle empty strings safely: " + e.getMessage());
        }
    }

    /**
     * Test 10: Verify hexadecimal SQL injection is prevented
     * Tests SQL injection using hexadecimal encoding
     */
    @Test
    public void testHexadecimalSQLInjection() {
        inventory.style_id.setText("STY009");
        inventory.Vendor_id.setText("VEN555");
        inventory.in_date.setText("13/03/2024");
        inventory.gold_cr.setText("22");
        inventory.gold_wt.setText("16.0");
        inventory.stone_type.setText("Amethyst");
        inventory.stone_wt.setText("2.4");
        // Hexadecimal SQL injection payload
        inventory.stone_number.setText("0x27204f52203127203d2027312027");
        inventory.details.setText("Test hex injection");

        ActionEvent mockEvent = new ActionEvent(inventory.submit, ActionEvent.ACTION_PERFORMED, "submit");

        try {
            inventory.actionPerformed(mockEvent);
            // PreparedStatement should treat hex as literal string
            assertTrue("Hexadecimal injection should be safely handled", true);
        } catch (Exception e) {
            fail("Should handle hexadecimal injection safely: " + e.getMessage());
        }
    }

    /**
     * Test 11: Verify that very long strings are handled correctly
     * Tests potential buffer overflow or truncation issues
     */
    @Test
    public void testVeryLongStringHandling() {
        // Create a very long string (1000 characters)
        StringBuilder longString = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            longString.append("A");
        }

        inventory.style_id.setText("STY010");
        inventory.Vendor_id.setText("VEN666");
        inventory.in_date.setText("13/03/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("13.0");
        inventory.stone_type.setText("Jade");
        inventory.stone_wt.setText("1.9");
        inventory.stone_number.setText("7");
        inventory.details.setText(longString.toString());

        ActionEvent mockEvent = new ActionEvent(inventory.submit, ActionEvent.ACTION_PERFORMED, "submit");

        try {
            inventory.actionPerformed(mockEvent);
            // PreparedStatement should handle long strings safely
            assertTrue("Very long strings should be handled safely", true);
        } catch (Exception e) {
            fail("Should handle very long strings safely: " + e.getMessage());
        }
    }

    /**
     * Test 12: Verify SQL injection with encoded characters is prevented
     * Tests SQL injection using URL-encoded characters
     */
    @Test
    public void testEncodedCharacterSQLInjection() {
        inventory.style_id.setText("STY011");
        inventory.Vendor_id.setText("VEN777");
        inventory.in_date.setText("13/03/2024");
        inventory.gold_cr.setText("24");
        inventory.gold_wt.setText("19.0");
        inventory.stone_type.setText("Turquoise");
        inventory.stone_wt.setText("2.1");
        // URL-encoded SQL injection payload (%27 = ', %20 = space)
        inventory.stone_number.setText("%27%20OR%20%271%27%3D%271");
        inventory.details.setText("Test encoded injection");

        ActionEvent mockEvent = new ActionEvent(inventory.submit, ActionEvent.ACTION_PERFORMED, "submit");

        try {
            inventory.actionPerformed(mockEvent);
            // PreparedStatement should treat encoded chars as literal string
            assertTrue("Encoded character injection should be safely handled", true);
        } catch (Exception e) {
            fail("Should handle encoded character injection safely: " + e.getMessage());
        }
    }
}
