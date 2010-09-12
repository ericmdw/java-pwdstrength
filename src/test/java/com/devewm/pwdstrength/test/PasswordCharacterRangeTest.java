package com.devewm.pwdstrength.test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Method;

import org.junit.Test;

import com.devewm.pwdstrength.PasswordCharacterRange;

public class PasswordCharacterRangeTest {
	
	@Test
	public void codepointCoverage() throws Exception {
		Class<?> pcr = PasswordCharacterRange.class;
		Class<?>[] pcrClasses = pcr.getDeclaredClasses();
		Class<?> characterBlockClass = null;
		for(Class<?> candidate : pcrClasses) {
			String candidateName = candidate.getSimpleName();
			if("CharacterBlock".equals(candidateName)) {
				characterBlockClass = candidate;
				break;
			}
		}
		Object[] characterBlocks = characterBlockClass.getEnumConstants();
		Method blockContainsMethod = null;
		for(Method candidate : characterBlockClass.getDeclaredMethods()) {
			if("contains".equals(candidate.getName())) {
				blockContainsMethod = candidate;
				break;
			}
		}
		
		System.out.println("Verifying all unicode character ranges have been defined.");
		System.out.println("Scanning entire unicode range (could take a while)...");
		
		for(int i = 1; i <= Character.MAX_CODE_POINT; i++) {
			boolean blockAlreadyFound = false;
			for(Object characterBlock : characterBlocks) {
				boolean blockFound = (Boolean) blockContainsMethod.invoke(characterBlock, i);
				
				assertFalse("Codepoint 0x" + Integer.toHexString(i) + " must not occur in multiple blocks", blockFound && blockAlreadyFound);
				
				if(blockFound) {
					blockAlreadyFound = true;
				}
			}
			
			assertTrue("Block required for codePoint: 0x" + Integer.toHexString(i), blockAlreadyFound);
		}
		
		System.out.println("Finished unicode range scan.");
	}
}
