package b_c.unbearable.messages;

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

    boolean isProvided()
    {
        return type == PROVIDED;
    }

    boolean isReferred()
    {
        return type == REFERRED;
    }

    boolean isKnownType()
    {
        return isProvided() || isReferred();
    }
}
