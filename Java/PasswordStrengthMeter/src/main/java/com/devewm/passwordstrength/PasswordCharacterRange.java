package com.devewm.passwordstrength;

/**
 * Defines common ranges of characters across which a brute-force attack
 * could run. 
 * @author eric
 *
 */
public enum PasswordCharacterRange {
	MINIMAL_FOR_INPUT(0,0),
	
	ALPHABET_LOWER_CASE(97, 122),
	ALPHABET_MIXED_CASE(65, 122),
	ALPHABET_AND_NUMBERS(48, 122),
	
	ASCII(0,127),
	
	UTF8(0,255),
	UTF16(0, (int) Math.pow(2, 16) - 1),
	UTF32(0, (int) Math.pow(2, 32) - 1);
	
	private int lowerBound;
	private int  upperBound;

	private PasswordCharacterRange(int lowerBound, int upperBound) {
		this.lowerBound = lowerBound;
		this.upperBound = upperBound;
	}
	
	public int getLowerBound() {
		return this.lowerBound;
	}
	
	public int getUpperBound() {
		return this.upperBound;
	}
}
