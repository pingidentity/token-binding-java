package b_c.unbearable.messages;

/**
 *
 */
public class TokenBindingType
{
    public static final int PROVIDED = 0;
    public static final int REFERRED = 1;

    private int type;

    public TokenBindingType(int type)
    {
        this.type = type;
    }

    public int getType()
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
