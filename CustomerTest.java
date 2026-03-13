import org.junit.Before;
import org.junit.After;
import org.junit.Test;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.sql.*;
import java.awt.event.ActionEvent;
import javax.swing.*;

/**
 * Comprehensive test suite for Customer class SQL injection remediation
 * Tests verify that the PreparedStatement implementation properly prevents SQL injection attacks
 * while maintaining the correct functionality of customer data insertion
 */
public class CustomerTest {

    private Customer customer;
    private Connection mockConnection;
    private PreparedStatement mockPreparedStatement;
    private ActionEvent mockActionEvent;

    @Before
    public void setUp() throws Exception {
        customer = new Customer();

        // Create mock objects for database components
        mockConnection = mock(Connection.class);
        mockPreparedStatement = mock(PreparedStatement.class);
        mockActionEvent = mock(ActionEvent.class);

        // Inject mock connection (using reflection to access private field)
        java.lang.reflect.Field conField = Customer.class.getDeclaredField("con");
        conField.setAccessible(true);
        conField.set(customer, mockConnection);

        // Setup mock behavior
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);
    }

    @After
    public void tearDown() {
        customer = null;
        mockConnection = null;
        mockPreparedStatement = null;
        mockActionEvent = null;
    }

    /**
     * Test that PreparedStatement is used instead of Statement
     * This is the core fix for SQL injection vulnerability
     */
    @Test
    public void testUsesPreparedStatementNotStatement() throws Exception {
        // Inject test data into text fields
        setTextFieldValue("Date_In", "01/01/2024");
        setTextFieldValue("Customer_Name", "John Doe");
        setTextFieldValue("Address", "123 Main St");
        setTextFieldValue("Phone", "555-1234");
        setTextFieldValue("Wedding_Aniv", "15/06/2020");
        setTextFieldValue("Birthday", "10/05/1990");
        setTextFieldValue("Ring_Husband", "10");
        setTextFieldValue("Ring_Wife", "8");
        setTextFieldValue("Ring_Other", "9");
        setTextFieldValue("Visits", "5");
        setTextFieldValue("credit", "1000");
        setTextFieldValue("Style_Id", "ST001");
        setTextFieldValue("Remark", "Good customer");

        // Trigger the action
        customer.actionPerformed(mockActionEvent);

        // Verify PreparedStatement was created with parameterized query
        verify(mockConnection).prepareStatement(contains("?"));
        verify(mockConnection).prepareStatement(
            eq("INSERT INTO Customer(Date_In,Name,Address,Phone,Wedding_Aniv,Birthday,Ring_Husband,Ring_Wife,Ring_Other,Visits,credit,Style_Id,Remark) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)")
        );
    }

    /**
     * Test that SQL injection attempt in customer name is properly escaped
     * Malicious input: ' OR '1'='1
     */
    @Test
    public void testSQLInjectionInCustomerNameIsBlocked() throws Exception {
        String maliciousName = "' OR '1'='1";

        setTextFieldValue("Date_In", "01/01/2024");
        setTextFieldValue("Customer_Name", maliciousName);
        setTextFieldValue("Address", "123 Main St");
        setTextFieldValue("Phone", "555-1234");
        setTextFieldValue("Wedding_Aniv", "15/06/2020");
        setTextFieldValue("Birthday", "10/05/1990");
        setTextFieldValue("Ring_Husband", "10");
        setTextFieldValue("Ring_Wife", "8");
        setTextFieldValue("Ring_Other", "9");
        setTextFieldValue("Visits", "5");
        setTextFieldValue("credit", "1000");
        setTextFieldValue("Style_Id", "ST001");
        setTextFieldValue("Remark", "Test");

        customer.actionPerformed(mockActionEvent);

        // Verify that setString is called with the malicious input as-is
        // PreparedStatement will automatically escape it
        verify(mockPreparedStatement).setString(2, maliciousName);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test SQL injection attempt using UNION SELECT attack in address field
     */
    @Test
    public void testSQLInjectionUnionAttackIsBlocked() throws Exception {
        String maliciousAddress = "'; DROP TABLE Customer; --";

        setTextFieldValue("Date_In", "01/01/2024");
        setTextFieldValue("Customer_Name", "Test User");
        setTextFieldValue("Address", maliciousAddress);
        setTextFieldValue("Phone", "555-1234");
        setTextFieldValue("Wedding_Aniv", "15/06/2020");
        setTextFieldValue("Birthday", "10/05/1990");
        setTextFieldValue("Ring_Husband", "10");
        setTextFieldValue("Ring_Wife", "8");
        setTextFieldValue("Ring_Other", "9");
        setTextFieldValue("Visits", "5");
        setTextFieldValue("credit", "1000");
        setTextFieldValue("Style_Id", "ST001");
        setTextFieldValue("Remark", "Test");

        customer.actionPerformed(mockActionEvent);

        // Verify PreparedStatement treats malicious input as literal string
        verify(mockPreparedStatement).setString(3, maliciousAddress);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test SQL injection attempt with comment injection in remark field
     */
    @Test
    public void testSQLInjectionCommentAttackIsBlocked() throws Exception {
        String maliciousRemark = "Test'; DELETE FROM Customer WHERE '1'='1";

        setTextFieldValue("Date_In", "01/01/2024");
        setTextFieldValue("Customer_Name", "Test User");
        setTextFieldValue("Address", "123 Main St");
        setTextFieldValue("Phone", "555-1234");
        setTextFieldValue("Wedding_Aniv", "15/06/2020");
        setTextFieldValue("Birthday", "10/05/1990");
        setTextFieldValue("Ring_Husband", "10");
        setTextFieldValue("Ring_Wife", "8");
        setTextFieldValue("Ring_Other", "9");
        setTextFieldValue("Visits", "5");
        setTextFieldValue("credit", "1000");
        setTextFieldValue("Style_Id", "ST001");
        setTextFieldValue("Remark", maliciousRemark);

        customer.actionPerformed(mockActionEvent);

        // Verify all parameters are set using PreparedStatement
        verify(mockPreparedStatement).setString(13, maliciousRemark);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that all 13 parameters are correctly set in PreparedStatement
     */
    @Test
    public void testAllParametersAreSetCorrectly() throws Exception {
        setTextFieldValue("Date_In", "01/01/2024");
        setTextFieldValue("Customer_Name", "John Doe");
        setTextFieldValue("Address", "123 Main St");
        setTextFieldValue("Phone", "555-1234");
        setTextFieldValue("Wedding_Aniv", "15/06/2020");
        setTextFieldValue("Birthday", "10/05/1990");
        setTextFieldValue("Ring_Husband", "10");
        setTextFieldValue("Ring_Wife", "8");
        setTextFieldValue("Ring_Other", "9");
        setTextFieldValue("Visits", "5");
        setTextFieldValue("credit", "1000");
        setTextFieldValue("Style_Id", "ST001");
        setTextFieldValue("Remark", "Good customer");

        customer.actionPerformed(mockActionEvent);

        // Verify each parameter is set with correct index and value
        verify(mockPreparedStatement).setString(1, "01/01/2024");
        verify(mockPreparedStatement).setString(2, "John Doe");
        verify(mockPreparedStatement).setString(3, "123 Main St");
        verify(mockPreparedStatement).setString(4, "555-1234");
        verify(mockPreparedStatement).setString(5, "15/06/2020");
        verify(mockPreparedStatement).setString(6, "10/05/1990");
        verify(mockPreparedStatement).setString(7, "10");
        verify(mockPreparedStatement).setString(8, "8");
        verify(mockPreparedStatement).setString(9, "9");
        verify(mockPreparedStatement).setString(10, "5");
        verify(mockPreparedStatement).setString(11, "1000");
        verify(mockPreparedStatement).setString(12, "ST001");
        verify(mockPreparedStatement).setString(13, "Good customer");

        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test with special characters that should be properly escaped
     */
    @Test
    public void testSpecialCharactersAreHandledCorrectly() throws Exception {
        String specialCharsName = "O'Brien & Sons";
        String specialCharsAddress = "123 \"Main\" St. <script>alert('xss')</script>";

        setTextFieldValue("Date_In", "01/01/2024");
        setTextFieldValue("Customer_Name", specialCharsName);
        setTextFieldValue("Address", specialCharsAddress);
        setTextFieldValue("Phone", "555-1234");
        setTextFieldValue("Wedding_Aniv", "15/06/2020");
        setTextFieldValue("Birthday", "10/05/1990");
        setTextFieldValue("Ring_Husband", "10");
        setTextFieldValue("Ring_Wife", "8");
        setTextFieldValue("Ring_Other", "9");
        setTextFieldValue("Visits", "5");
        setTextFieldValue("credit", "1000");
        setTextFieldValue("Style_Id", "ST001");
        setTextFieldValue("Remark", "Test");

        customer.actionPerformed(mockActionEvent);

        // Verify special characters are passed as-is to PreparedStatement
        verify(mockPreparedStatement).setString(2, specialCharsName);
        verify(mockPreparedStatement).setString(3, specialCharsAddress);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test with empty strings (edge case)
     */
    @Test
    public void testEmptyStringsAreHandledCorrectly() throws Exception {
        setTextFieldValue("Date_In", "");
        setTextFieldValue("Customer_Name", "");
        setTextFieldValue("Address", "");
        setTextFieldValue("Phone", "");
        setTextFieldValue("Wedding_Aniv", "");
        setTextFieldValue("Birthday", "");
        setTextFieldValue("Ring_Husband", "");
        setTextFieldValue("Ring_Wife", "");
        setTextFieldValue("Ring_Other", "");
        setTextFieldValue("Visits", "");
        setTextFieldValue("credit", "");
        setTextFieldValue("Style_Id", "");
        setTextFieldValue("Remark", "");

        customer.actionPerformed(mockActionEvent);

        // Verify empty strings are handled
        for (int i = 1; i <= 13; i++) {
            verify(mockPreparedStatement).setString(eq(i), eq(""));
        }
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test with very long strings (boundary test)
     */
    @Test
    public void testLongStringsAreHandledCorrectly() throws Exception {
        String longAddress = new String(new char[500]).replace('\0', 'A');
        String longRemark = new String(new char[500]).replace('\0', 'B');

        setTextFieldValue("Date_In", "01/01/2024");
        setTextFieldValue("Customer_Name", "Test User");
        setTextFieldValue("Address", longAddress);
        setTextFieldValue("Phone", "555-1234");
        setTextFieldValue("Wedding_Aniv", "15/06/2020");
        setTextFieldValue("Birthday", "10/05/1990");
        setTextFieldValue("Ring_Husband", "10");
        setTextFieldValue("Ring_Wife", "8");
        setTextFieldValue("Ring_Other", "9");
        setTextFieldValue("Visits", "5");
        setTextFieldValue("credit", "1000");
        setTextFieldValue("Style_Id", "ST001");
        setTextFieldValue("Remark", longRemark);

        customer.actionPerformed(mockActionEvent);

        // Verify long strings are passed correctly
        verify(mockPreparedStatement).setString(3, longAddress);
        verify(mockPreparedStatement).setString(13, longRemark);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test SQL injection with multiple single quotes
     */
    @Test
    public void testMultipleSingleQuotesAreEscaped() throws Exception {
        String multiQuoteName = "''''''";

        setTextFieldValue("Date_In", "01/01/2024");
        setTextFieldValue("Customer_Name", multiQuoteName);
        setTextFieldValue("Address", "123 Main St");
        setTextFieldValue("Phone", "555-1234");
        setTextFieldValue("Wedding_Aniv", "15/06/2020");
        setTextFieldValue("Birthday", "10/05/1990");
        setTextFieldValue("Ring_Husband", "10");
        setTextFieldValue("Ring_Wife", "8");
        setTextFieldValue("Ring_Other", "9");
        setTextFieldValue("Visits", "5");
        setTextFieldValue("credit", "1000");
        setTextFieldValue("Style_Id", "ST001");
        setTextFieldValue("Remark", "Test");

        customer.actionPerformed(mockActionEvent);

        verify(mockPreparedStatement).setString(2, multiQuoteName);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test SQL injection attempt with hex encoding
     */
    @Test
    public void testHexEncodedSQLInjectionIsBlocked() throws Exception {
        String hexEncodedAttack = "0x53454c454354202a2046524f4d2043757374";

        setTextFieldValue("Date_In", "01/01/2024");
        setTextFieldValue("Customer_Name", "Test User");
        setTextFieldValue("Address", hexEncodedAttack);
        setTextFieldValue("Phone", "555-1234");
        setTextFieldValue("Wedding_Aniv", "15/06/2020");
        setTextFieldValue("Birthday", "10/05/1990");
        setTextFieldValue("Ring_Husband", "10");
        setTextFieldValue("Ring_Wife", "8");
        setTextFieldValue("Ring_Other", "9");
        setTextFieldValue("Visits", "5");
        setTextFieldValue("credit", "1000");
        setTextFieldValue("Style_Id", "ST001");
        setTextFieldValue("Remark", "Test");

        customer.actionPerformed(mockActionEvent);

        verify(mockPreparedStatement).setString(3, hexEncodedAttack);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that the query does NOT use string concatenation
     * This is a regression test to ensure the vulnerability fix remains in place
     */
    @Test
    public void testQueryDoesNotUseStringConcatenation() throws Exception {
        setTextFieldValue("Date_In", "01/01/2024");
        setTextFieldValue("Customer_Name", "John Doe");
        setTextFieldValue("Address", "123 Main St");
        setTextFieldValue("Phone", "555-1234");
        setTextFieldValue("Wedding_Aniv", "15/06/2020");
        setTextFieldValue("Birthday", "10/05/1990");
        setTextFieldValue("Ring_Husband", "10");
        setTextFieldValue("Ring_Wife", "8");
        setTextFieldValue("Ring_Other", "9");
        setTextFieldValue("Visits", "5");
        setTextFieldValue("credit", "1000");
        setTextFieldValue("Style_Id", "ST001");
        setTextFieldValue("Remark", "Good customer");

        customer.actionPerformed(mockActionEvent);

        // Verify the query string contains placeholders, not actual values
        verify(mockConnection).prepareStatement(argThat(query ->
            query != null &&
            query.contains("?") &&
            !query.contains("John Doe") &&
            !query.contains("123 Main St")
        ));
    }

    /**
     * Helper method to set text field values using reflection
     */
    private void setTextFieldValue(String fieldName, String value) throws Exception {
        java.lang.reflect.Field field = Customer.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        JTextField textField = (JTextField) field.get(customer);
        if (textField == null) {
            textField = new JTextField();
            field.set(customer, textField);
        }
        textField.setText(value);
    }
}
