package com.devewm.passwordstrength;

import java.util.HashSet;
import java.util.Set;

/**
 * Defines common classes of characters across which a brute-force attack
 * could run. 
 * @author eric
 *
 */
public enum PasswordCharacterRange {
	LETTERS_BASIC_LATIN_LOWER_CASE(new Range(97, 122)),
	LETTERS_BASIC_LATIN_UPPER_CASE(new Range(65, 90)),
	NUMERICAL_DIGITS(new Range(48,57)),
	
	SYMBOLS_BASIC_LATIN(
			new Range(32, 47),
			new Range(58, 64),
			new Range(91, 96),
			new Range(123, 126),
			new Range(160, 191)),
	
	CONTROL_CHARACTERS_BASIC_LATIN(
			new Range(0,31), 
			new Range(127, 159)),
	
	LETTERS_EXTENDED_LATIN_LOWER_CASE(new Range(223,246)),
	
	LETTERS_EXTENDED_LATIN_UPPER_CASE(
			new Range(192, 214),
			new Range(216, 222)),
	
	SYMBOLS_EXTENDED_LATIN(
			new Range(215,215),
			new Range(247,247),
			new Range(248, 255));
	
	private Set<Range> characters;

	private PasswordCharacterRange(Range... ranges) {
		characters = new HashSet<Range>();
		if(null != ranges && ranges.length > 0) {
			for(Range range : ranges) {
				characters.add(range);
			}
		}
	}
	
	private PasswordCharacterRange(PasswordCharacterRange... subRanges) {
		if(null != subRanges && subRanges.length > 0) {
			for(PasswordCharacterRange range : subRanges) {
				this.characters.addAll(range.characters);
			}
		}
	}
	
	public boolean contains(char character) {
		for(Range range : characters) {
			if(range.lowerBound <= character && range.upperBound >= character) {
				return true;
			}
		}
		
		return false;
	}
	
	public long size() {
		long result = 0;
		for(Range range : characters) {
			result += (range.upperBound - range.lowerBound) + 1;
		}
		return result;
	}
	
	public long position(char character) {
		long count = 0;
		for(Range range : characters) {
			if(range.lowerBound <= character && range.upperBound >= character) {
				return count + (character - range.lowerBound);
			} else {
				count += (range.upperBound - range.lowerBound) + 1;
			}
		}
		
		return -1;
	}
	
	private static class Range {
		private long lowerBound, upperBound;
		public Range(long lowerBound, long upperBound) {
			this.lowerBound = lowerBound;
			this.upperBound = upperBound;
		}
	}
}
