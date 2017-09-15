package b_c.unbearable.server;

/**
 *
 */
public class TBException extends Exception
{
    public TBException(String message)
    {
        super(message);
    }

    public TBException(String message, Throwable cause)
    {
        super(message, cause);
    }
}
