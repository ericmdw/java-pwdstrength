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
		
		password = "b";
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
	public void twoLetterPasswords() {
		String password;
		PasswordCharacterRange range;
		long result;
		
		password = "aa";
		range = PasswordCharacterRange.MINIMAL_FOR_INPUT;
		result = PasswordStrengthMeter.check(password, range);
		assertEquals(2, result);
		
		password = "ab";
		range = PasswordCharacterRange.MINIMAL_FOR_INPUT;
		result = PasswordStrengthMeter.check(password, range);
		assertEquals(4, result);
		
		password = "ba";
		range = PasswordCharacterRange.MINIMAL_FOR_INPUT;
		result = PasswordStrengthMeter.check(password, range);
		assertEquals(5, result);
	}
	
	@Test
	public void threeLetterPasswords() {
		String password;
		PasswordCharacterRange range;
		long result;
		
		// 1. a
		// 2. b
		// 3. c
		// 4. aa
		// 5. ab
		// 6. ac
		// 7. ba
		// 8. bb
		// 9. bc
		//10. ca
		//11. cb
		//12. cc
		//13. aaa
		//14. aab
		//15. aac
		//16. aba
		//17. abb
		//18. abc
		//19. aca
		//20. acb
		//21. acc
		//22. baa
		//23. bab
		//24. bac
		//25. bba
		//26. bbb
		//27. bbc
		//28. bca
		//29. bcb
		//30. bcc
		//31. caa
		//32. cab
		//33. cac
		//34. cba
		//35. cbb
		//36. cbc
		//37. cca
		//38. ccb
		//39. ccc
		
		password = "abc";
		range = PasswordCharacterRange.MINIMAL_FOR_INPUT;
		result = PasswordStrengthMeter.check(password, range);
		assertEquals(18, result);
		
		password = "acb";
		range = PasswordCharacterRange.MINIMAL_FOR_INPUT;
		result = PasswordStrengthMeter.check(password, range);
		assertEquals(20, result);
		
		password = "bac";
		range = PasswordCharacterRange.MINIMAL_FOR_INPUT;
		result = PasswordStrengthMeter.check(password, range);
		assertEquals(24, result);
		
		password = "cab";
		range = PasswordCharacterRange.MINIMAL_FOR_INPUT;
		result = PasswordStrengthMeter.check(password, range);
		assertEquals(32, result);
		
		password = "cba";
		range = PasswordCharacterRange.MINIMAL_FOR_INPUT;
		result = PasswordStrengthMeter.check(password, range);
		assertEquals(34, result);
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
