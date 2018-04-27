package com.pingidentity.oss.unbearable;

/**
 *
 */
public class TokenBindingException extends Exception
{
    public TokenBindingException(String message)
    {
        super(message);
    }

    public TokenBindingException(String message, Throwable cause)
    {
        super(message, cause);
    }
}
