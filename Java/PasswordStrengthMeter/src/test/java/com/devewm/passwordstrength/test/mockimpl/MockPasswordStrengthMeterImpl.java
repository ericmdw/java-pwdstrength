package com.devewm.passwordstrength.test.mockimpl;

import java.math.BigInteger;

import com.devewm.passwordstrength.PasswordStrengthMeter;

public class MockPasswordStrengthMeterImpl extends PasswordStrengthMeter {
	
	@Override
	public BigInteger iterationCount(String passwordPlaintext, boolean bypassLengthLimitCheck) {
		return new BigInteger("-1");
	}
	
}
