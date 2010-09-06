package com.devewm.pwdstrength.test.mockimpl;

import java.math.BigInteger;

import com.devewm.pwdstrength.PasswordStrengthMeter;

public class MockPasswordStrengthMeterImpl extends PasswordStrengthMeter {
	
	@Override
	public BigInteger iterationCount(String passwordPlaintext, boolean bypassLengthLimitCheck) {
		return new BigInteger("-1");
	}
	
}
