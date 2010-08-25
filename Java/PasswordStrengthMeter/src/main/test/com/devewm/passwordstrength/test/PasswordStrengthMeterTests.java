package com.devewm.passwordstrength.test;

import static org.junit.Assert.*;

//import java.text.DecimalFormat;

import org.junit.Test;

import com.devewm.passwordstrength.PasswordCharacterRange;
import com.devewm.passwordstrength.PasswordStrengthMeter;


public class PasswordStrengthMeterTests {
	
	@Test
	public void singleLetterPasswords() {
		String password;
		PasswordCharacterRange range;
		long result;
		
		password = "a";
		range = PasswordCharacterRange.MINIMAL_FOR_INPUT;
		result = PasswordStrengthMeter.check(password, range);
		assertEquals(1, result);
		
		password = "z";
		range = PasswordCharacterRange.MINIMAL_FOR_INPUT;
		result = PasswordStrengthMeter.check(password, range);
		assertEquals(1, result);
		
		password = "0";
		range = PasswordCharacterRange.MINIMAL_FOR_INPUT;
		result = PasswordStrengthMeter.check(password, range);
		assertEquals(1, result);
		
		password = "a";
		range = PasswordCharacterRange.ALPHABET_LOWER_CASE;
		result = PasswordStrengthMeter.check(password, range);
		assertEquals(1, result);
		
		password = "b";
		range = PasswordCharacterRange.ALPHABET_LOWER_CASE;
		result = PasswordStrengthMeter.check(password, range);
		assertEquals(2, result);
		assertEquals('b' - 'a' + 1, result);
	}
	
	@Test
	public void outOfRangePasswords() {
		String password;
		PasswordCharacterRange range;
		long result;
		
		password = "a";
		range = PasswordCharacterRange.ALPHABET_LOWER_CASE;
		result = PasswordStrengthMeter.check(password, range);
		assertEquals(1, result);
		
		password = "A";
		range = PasswordCharacterRange.ALPHABET_LOWER_CASE;
		result = PasswordStrengthMeter.check(password, range);
		assertEquals('a' - 'A' + 1, result);
		
		password = "0";
		range = PasswordCharacterRange.ALPHABET_LOWER_CASE;
		result = PasswordStrengthMeter.check(password, range);
		assertEquals('a' - '0' + 1, result);
	}
	
	@Test
	public void commonPasswords() {
		// DecimalFormat number = new DecimalFormat();
		// number.setGroupingUsed(true);
		
		String password;
		PasswordCharacterRange range;
		long result;
		
		password = "123456";
		range = PasswordCharacterRange.MINIMAL_FOR_INPUT;
		result = PasswordStrengthMeter.check(password, range);
		assertEquals(3130, result);
		// System.out.println("Password: " + password + "\nIterations: " + number.format(result));
		
		password = "jesus";
		range = PasswordCharacterRange.MINIMAL_FOR_INPUT;
		result = PasswordStrengthMeter.check(password, range);
		assertEquals(65550, result);
		// System.out.println("Password: " + password + "\nIterations: " + number.format(result));
		
		password = "password";
		range = PasswordCharacterRange.MINIMAL_FOR_INPUT;
		result = PasswordStrengthMeter.check(password, range);
		assertEquals(2494357891L, result);
		// System.out.println("Password: " + password + "\nIterations: " + number.format(result));
		
		password = "love";
		range = PasswordCharacterRange.MINIMAL_FOR_INPUT;
		result = PasswordStrengthMeter.check(password, range);
		assertEquals(4913, result);
		// System.out.println("Password: " + password + "\nIterations: " + number.format(result));
		
		password = "12345678";
		range = PasswordCharacterRange.MINIMAL_FOR_INPUT;
		result = PasswordStrengthMeter.check(password, range);
		assertEquals(823550, result);
		// System.out.println("Password: " + password + "\nIterations: " + number.format(result));
		
		password = "christ";
		range = PasswordCharacterRange.MINIMAL_FOR_INPUT;
		result = PasswordStrengthMeter.check(password, range);
		assertEquals(1419874, result);
		// System.out.println("Password: " + password + "\nIterations: " + number.format(result));
		
		password = "jesus1";
		range = PasswordCharacterRange.MINIMAL_FOR_INPUT;
		result = PasswordStrengthMeter.check(password, range);
		assertEquals(1453933568, result);
		// System.out.println("Password: " + password + "\nIterations: " + number.format(result));
		
		password = "princess";
		range = PasswordCharacterRange.MINIMAL_FOR_INPUT;
		result = PasswordStrengthMeter.check(password, range);
		assertEquals(268435472, result);
		// System.out.println("Password: " + password + "\nIterations: " + number.format(result));
		
		password = "blessed";
		range = PasswordCharacterRange.MINIMAL_FOR_INPUT;
		result = PasswordStrengthMeter.check(password, range);
		assertEquals(24137571, result);
		// System.out.println("Password: " + password + "\nIterations: " + number.format(result));
		
		password = "sunshine";
		range = PasswordCharacterRange.MINIMAL_FOR_INPUT;
		result = PasswordStrengthMeter.check(password, range);
		assertEquals(268435456, result);
		// System.out.println("Password: " + password + "\nIterations: " + number.format(result));
	}
	
}
