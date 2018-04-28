package com.pingidentity.oss.unbearable.messages;

/**
 *
 */
public class TokenBindingType
{
    public static final byte PROVIDED = 0;
    public static final byte REFERRED = 1;

    private byte type;

    public TokenBindingType(byte type)
    {
        this.type = type;
    }

    public byte getType()
    {
        return type;
    }

    public boolean isProvided()
    {
        return type == PROVIDED;
    }

    public boolean isReferred()
    {
        return type == REFERRED;
    }
}
