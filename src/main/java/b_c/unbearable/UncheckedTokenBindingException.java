package b_c.unbearable;

/**
 *
 */
public class UncheckedTokenBindingException extends RuntimeException
{
    public UncheckedTokenBindingException(String message)
    {
        super(message);
    }

    public UncheckedTokenBindingException(String message, Throwable cause)
    {
        super(message, cause);
    }
}
