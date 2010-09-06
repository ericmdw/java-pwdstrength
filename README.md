# Password Strength Meter

*by Eric Montgomery*

*<http://devewm.com/projects/pwdstrength>*

## Description
This utility aims to make it easy to determine and categorize the complexity of a password, hopefully simplifying writing validators for setting account passwords. By allowing or disallowing a password to be set based on its complexity alone, you remove the need for arbitrary restrictions like "must contain at least one upper-case letter and one number", "must contain at least one non-alphanumeric symbol", etc. This allows users to more freely choose passwords that fit their preferences while still enforcing some minimum level of security.

Password length also becomes less of an issue. For instance, the password "ئЖjΩ☮" has higher brute-force resistance than "aJ@2fz0z" while not actually satisfying the basic length requirement of passwords on most systems. Password Strength Meter classifies passwords based on their resistance to brute-force attack, allowing you to run only one check on a prospective password and allowing it if it meets the basic complexity level criteria you have specified.

## Usage
Get an instance of the `PasswordStrengthMeter` class and then use the `satisfiesStrengthClass` method. 

Example:


    PasswordStrengthMeter passwordStrengthMeter = PasswordStrengthMeter.getInstance();
    boolean passwordSecure = passwordStrengthMeter.satisfiesStrengthClass(
        "pAssword123", PasswordStrengthClass.LENGTH_10_MIXED_CASE_WITH_NUMBER);


You can also get the number of iterations it would take to guess the given password. Example:


    BigInteger result = passwordStrengthMeter.iterationCount("pAssword123");


(Note that the iteration count assumes a naive, sequential approach to password generation. A brute force password utility may generate its guesses more effctively, i.e. by using statistical models or dictionary word lists, and so may be able to reach the password more quickly than the result indicates.)

## License
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org/>