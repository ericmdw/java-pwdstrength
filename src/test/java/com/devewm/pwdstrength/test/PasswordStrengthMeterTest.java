package com.devewm.pwdstrength.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.util.Random;

import org.junit.Before;
import org.junit.Test;

import com.devewm.pwdstrength.PasswordStrengthClass;
import com.devewm.pwdstrength.PasswordStrengthMeter;
import com.devewm.pwdstrength.exception.MaximumPasswordLengthExceededException;
import com.devewm.pwdstrength.test.benchmark.Benchmark;
import com.devewm.pwdstrength.test.mockimpl.MockPasswordStrengthMeterImpl;

public class PasswordStrengthMeterTest {
	
	private PasswordStrengthMeter passwordStrengthMeter;
	
	@Before
	public void setupDefaultImpl() throws Exception {
		this.passwordStrengthMeter = PasswordStrengthMeter.getInstance();
		
		Field field = PasswordStrengthMeter.class.getDeclaredField("verifyPartialSumResult");
		if(!field.isAccessible()) {
			field.setAccessible(true);
		}
		
		field.set(passwordStrengthMeter, true);
	}
	
	@Test
	public void testCodePoints() {
		assertEquals((int) ' ', 32);
		assertEquals((int) 'A', 65);
		assertEquals((int) 'a', 97);
		assertEquals((int) '¡', 161);
		
	}
	
	@Test
	public void singleLetterPasswords() throws MaximumPasswordLengthExceededException {
		String password;
		BigInteger result;
		
		password = "a";
		result = passwordStrengthMeter.iterationCount(password, false);
		assertEquals(new BigInteger("1"), result);
		
		password = "b";
		result = passwordStrengthMeter.iterationCount(password, false);
		assertEquals(new BigInteger("2"), result);
		
		password = "z";
		result = passwordStrengthMeter.iterationCount(password, false);
		assertEquals(new BigInteger("26"), result);
		
		password = "0";
		result = passwordStrengthMeter.iterationCount(password, false);
		assertEquals(new BigInteger("1"), result);
		
		password = "3";
		result = passwordStrengthMeter.iterationCount(password, false);
		assertEquals(new BigInteger("4"), result);
		
	}
	
	@Test
	public void twoLetterPasswords() throws MaximumPasswordLengthExceededException {
		String password;
		BigInteger result;
		
		password = "aa";
		result = passwordStrengthMeter.iterationCount(password, false);
		assertEquals(new BigInteger("27"), result);
		
		password = "ab";
		result = passwordStrengthMeter.iterationCount(password, false);
		assertEquals(new BigInteger("28"), result);
		
		password = "ba";
		result = passwordStrengthMeter.iterationCount(password, false);
		assertEquals(new BigInteger("53"), result);
	}
	
	@Test
	public void threeLetterPasswords() throws MaximumPasswordLengthExceededException {
		String password;
		BigInteger result;
		
		// 26^2 + 26^1 + 1
		password = "aaa";
		result = passwordStrengthMeter.iterationCount(password, false);
		assertEquals(new BigInteger("703"), result);
		
		// 26^2 + 26^1 + 1
		password = "AAA";
		result = passwordStrengthMeter.iterationCount(password, false);
		assertEquals(new BigInteger("703"), result);
		
		// (26^2 + 26^1) + 2
		password = "aab";
		result = passwordStrengthMeter.iterationCount(password, false);
		assertEquals(new BigInteger("704"), result);
		
		// (26^2 + 26^1) + 1*(26^2) + 1 = 1379
		password = "baa";
		result = passwordStrengthMeter.iterationCount(password, false);
		assertEquals(new BigInteger("1379"), result);
		
		// (36^2 + 36^1) + 26*(36^0) + 1 = 1359
		password = "aa0";
		result = passwordStrengthMeter.iterationCount(password, false);
		assertEquals(new BigInteger("1359"), result);
		
		// (62^2 + 62^1) + 26*(62^1) + 52*(62^0) + 1 = 5571
		password = "aA0";
		result = passwordStrengthMeter.iterationCount(password, false);
		assertEquals(new BigInteger("5571"), result);
		
		// (62^2 + 62^1) + 25*(62^2) + 27*(62^1) + 52*(62^0) + 1 = 101733
		password = "zB0";
		result = passwordStrengthMeter.iterationCount(password, false);
		assertEquals(new BigInteger("101733"), result);
		
	}
	
	@Test
	public void quickBrownFox() {
		String fox = "thequickbrownfoxjumpsoverthelazydog";
		
		BigInteger previousResult = null;
		for(int i = 1; i <= fox.length(); i++) {
			BigInteger result = passwordStrengthMeter.iterationCount(fox.substring(0,i));
			if(null != previousResult) {
				assertTrue("Adding a letter results in at least 10 times the number of iterations", 
						result.compareTo(previousResult.multiply(new BigInteger("10"))) > 0);
			}
			
			previousResult = result;
		}
	}
	
	@Test
	public void bigIntegerSizeLimit() {
		Random rand = new Random();
		StringBuffer password = new StringBuffer("");
		for(int i = 0; i < PasswordStrengthMeter.PASSWORD_LENGTH_LIMIT; i++) {
			password.append(Character.toChars(rand.nextInt(Character.MAX_CODE_POINT)));
			passwordStrengthMeter.iterationCount(password.toString());
		}
		
		Exception exception = null;
		try {
			password.append("a");
			passwordStrengthMeter.iterationCount(password.toString(), false);
		} catch(Exception ex) {
			exception = ex;
		}
		assertNotNull(exception);
		exception = null;
		
		try {
			passwordStrengthMeter.iterationCount(password.toString(), true);
		} catch (MaximumPasswordLengthExceededException e) {
			exception = e;
		}
		
		assertNull(exception);
	}
	
	@Test
	public void strengthClassifications() throws MaximumPasswordLengthExceededException {
		String password;
		BigInteger result;
		
		// 8 characters, all lower case
		password = "aaaaaaaa";
		assertTrue(password.length() == 8);
		result = passwordStrengthMeter.iterationCount(password, false);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_8_LOWER_CASE.getIterations()) >= 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_8_MIXED_CASE.getIterations()) < 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_8_MIXED_CASE_WITH_NUMBER.getIterations()) < 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_8_MIXED_CASE_WITH_NUMBER_AND_SYMBOL.getIterations()) < 0);
		
		// 8 characters mixed case
		password = "aaaaaaaA";
		assertTrue(password.length() == 8);
		result = passwordStrengthMeter.iterationCount(password, false);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_8_LOWER_CASE.getIterations()) > 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_8_MIXED_CASE.getIterations()) >= 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_8_MIXED_CASE_WITH_NUMBER.getIterations()) < 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_8_MIXED_CASE_WITH_NUMBER_AND_SYMBOL.getIterations()) < 0);
		
		// 8 characters mixed case plus a number
		password = "aaaaaaA0";
		assertTrue(password.length() == 8);
		result = passwordStrengthMeter.iterationCount(password, false);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_8_LOWER_CASE.getIterations()) > 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_8_MIXED_CASE.getIterations()) > 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_8_MIXED_CASE_WITH_NUMBER.getIterations()) >= 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_8_MIXED_CASE_WITH_NUMBER_AND_SYMBOL.getIterations()) < 0);
		
		// 8 characters mixed case plus a number and a non-alphanumeric symbol
		password = "aaaaaA0!";
		assertTrue(password.length() == 8);
		result = passwordStrengthMeter.iterationCount(password, false);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_8_LOWER_CASE.getIterations()) > 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_8_MIXED_CASE.getIterations()) > 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_8_MIXED_CASE_WITH_NUMBER.getIterations()) > 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_8_MIXED_CASE_WITH_NUMBER_AND_SYMBOL.getIterations()) >= 0);
		
		// 10 characters, all lower case
		password = "aaaaaaaaaa";
		assertTrue(password.length() == 10);
		result = passwordStrengthMeter.iterationCount(password, false);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_10_LOWER_CASE.getIterations()) >= 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_10_MIXED_CASE.getIterations()) < 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_10_MIXED_CASE_WITH_NUMBER.getIterations()) < 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_10_MIXED_CASE_WITH_NUMBER_AND_SYMBOL.getIterations()) < 0);
		
		// 10 characters mixed case
		password = "aaaaaaaaaA";
		assertTrue(password.length() == 10);
		result = passwordStrengthMeter.iterationCount(password, false);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_10_LOWER_CASE.getIterations()) > 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_10_MIXED_CASE.getIterations()) >= 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_10_MIXED_CASE_WITH_NUMBER.getIterations()) < 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_10_MIXED_CASE_WITH_NUMBER_AND_SYMBOL.getIterations()) < 0);
		
		// 10 characters mixed case plus a number
		password = "aaaaaaaaA0";
		assertTrue(password.length() == 10);
		result = passwordStrengthMeter.iterationCount(password, false);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_10_LOWER_CASE.getIterations()) > 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_10_MIXED_CASE.getIterations()) > 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_10_MIXED_CASE_WITH_NUMBER.getIterations()) >= 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_10_MIXED_CASE_WITH_NUMBER_AND_SYMBOL.getIterations()) < 0);
		
		// 10 characters mixed case plus a number and a non-alphanumeric symbol
		password = "aaaaaaaA0!";
		assertTrue(password.length() == 10);
		result = passwordStrengthMeter.iterationCount(password, false);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_10_LOWER_CASE.getIterations()) > 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_10_MIXED_CASE.getIterations()) > 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_10_MIXED_CASE_WITH_NUMBER.getIterations()) > 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_10_MIXED_CASE_WITH_NUMBER_AND_SYMBOL.getIterations()) >= 0);
		
		// 12 characters, all lower case
		password = "aaaaaaaaaaaa";
		assertTrue(password.length() == 12);
		result = passwordStrengthMeter.iterationCount(password, false);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_12_LOWER_CASE.getIterations()) >= 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_12_MIXED_CASE.getIterations()) < 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_12_MIXED_CASE_WITH_NUMBER.getIterations()) < 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_12_MIXED_CASE_WITH_NUMBER_AND_SYMBOL.getIterations()) < 0);
		
		// 12 characters mixed case
		password = "aaaaaaaaaaaA";
		assertTrue(password.length() == 12);
		result = passwordStrengthMeter.iterationCount(password, false);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_12_LOWER_CASE.getIterations()) > 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_12_MIXED_CASE.getIterations()) >= 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_12_MIXED_CASE_WITH_NUMBER.getIterations()) < 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_12_MIXED_CASE_WITH_NUMBER_AND_SYMBOL.getIterations()) < 0);
		
		// 12 characters mixed case plus a number
		password = "aaaaaaaaaaA0";
		assertTrue(password.length() == 12);
		result = passwordStrengthMeter.iterationCount(password, false);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_12_LOWER_CASE.getIterations()) > 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_12_MIXED_CASE.getIterations()) > 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_12_MIXED_CASE_WITH_NUMBER.getIterations()) >= 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_12_MIXED_CASE_WITH_NUMBER_AND_SYMBOL.getIterations()) < 0);
		
		// 12 characters mixed case plus a number and a non-alphanumeric symbol
		password = "aaaaaaaaaA0!";
		assertTrue(password.length() == 12);
		result = passwordStrengthMeter.iterationCount(password, false);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_12_LOWER_CASE.getIterations()) > 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_12_MIXED_CASE.getIterations()) > 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_12_MIXED_CASE_WITH_NUMBER.getIterations()) > 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_12_MIXED_CASE_WITH_NUMBER_AND_SYMBOL.getIterations()) >= 0);
		
		// 16 characters, all lower case
		password = "aaaaaaaaaaaaaaaa";
		assertTrue(password.length() == 16);
		result = passwordStrengthMeter.iterationCount(password, false);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_16_LOWER_CASE.getIterations()) >= 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_16_MIXED_CASE.getIterations()) < 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_16_MIXED_CASE_WITH_NUMBER.getIterations()) < 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_16_MIXED_CASE_WITH_NUMBER_AND_SYMBOL.getIterations()) < 0);
		
		// 16 characters mixed case
		password = "aaaaaaaaaaaaaaaA";
		assertTrue(password.length() == 16);
		result = passwordStrengthMeter.iterationCount(password, false);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_16_LOWER_CASE.getIterations()) > 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_16_MIXED_CASE.getIterations()) >= 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_16_MIXED_CASE_WITH_NUMBER.getIterations()) < 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_16_MIXED_CASE_WITH_NUMBER_AND_SYMBOL.getIterations()) < 0);
		
		// 16 characters mixed case plus a number
		password = "aaaaaaaaaaaaaaA0";
		assertTrue(password.length() == 16);
		result = passwordStrengthMeter.iterationCount(password, false);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_16_LOWER_CASE.getIterations()) > 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_16_MIXED_CASE.getIterations()) > 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_16_MIXED_CASE_WITH_NUMBER.getIterations()) >= 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_16_MIXED_CASE_WITH_NUMBER_AND_SYMBOL.getIterations()) < 0);
		
		// 16 characters mixed case plus a number and a non-alphanumeric symbol
		password = "aaaaaaaaaaaaaA0!";
		assertTrue(password.length() == 16);
		result = passwordStrengthMeter.iterationCount(password, false);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_16_LOWER_CASE.getIterations()) > 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_16_MIXED_CASE.getIterations()) > 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_16_MIXED_CASE_WITH_NUMBER.getIterations()) > 0);
		assertTrue(result.compareTo(PasswordStrengthClass.LENGTH_16_MIXED_CASE_WITH_NUMBER_AND_SYMBOL.getIterations()) >= 0);
		
	}
	
	@Test
	public void customImpl() {
		PasswordStrengthMeter defaultMeter = PasswordStrengthMeter.getInstance();
		PasswordStrengthMeter customSingletonMeter = PasswordStrengthMeter.getInstance(MockPasswordStrengthMeterImpl.class);
		assertNotNull(defaultMeter);
		assertNotNull(customSingletonMeter);
		
		String password = "custom";
		BigInteger defaultResult = defaultMeter.iterationCount(password);
		BigInteger customResult = customSingletonMeter.iterationCount(password);
		
		assertTrue(defaultResult.compareTo(customResult) > 0);
		
		PasswordStrengthMeter customSingletonMeter2 = PasswordStrengthMeter.getInstance(customSingletonMeter.getClass());
		
		assertTrue(defaultMeter != customSingletonMeter);
		assertTrue(customSingletonMeter == customSingletonMeter2);
	}
	
	@Test
	public void benchmarkTest() {
		// this is really just to verify the partial-sum
		// algorithm in PasswordStrengthMeter. The result
		// of that algorithm is verified with a slower algorithm
		// when run in the context of a test.
		Benchmark.bench(10000);
	}
}
