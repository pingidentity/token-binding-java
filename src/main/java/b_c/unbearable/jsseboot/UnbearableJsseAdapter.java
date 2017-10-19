package b_c.unbearable.jsseboot;

import b_c.unbearable.UncheckedTokenBindingException;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 *
 */
public class UnbearableJsseAdapter
{
    public TlsTbInfo getTbInfo(SSLSocket sslSocket) throws NoSuchMethodException
    {
        return getTbInfo(sslSocket, sslSocket.getClass());
    }

    public TlsTbInfo getTbInfo(SSLEngine engine) throws NoSuchMethodException
    {
        return getTbInfo(engine, engine.getClass());
    }

    TlsTbInfo getTbInfo(Object object, Class<?> objectClass) throws NoSuchMethodException
    {
        try
        {
            Byte negotiatedKeyParamsId;
            byte[] ekm;
            Method tbKeyParamsMethod = objectClass.getMethod("getNegotiatedTokenBindingKeyParams");
            negotiatedKeyParamsId = (Byte)tbKeyParamsMethod.invoke(object);

            Method ekmMethod = objectClass.getMethod("exportKeyingMaterial", String.class, int.class);
            Object invoked = ekmMethod.invoke(object, "EXPORTER-Token-Binding", 32);
            ekm = (byte[]) invoked;
            return new TlsTbInfo(negotiatedKeyParamsId, ekm);
        }
        catch (IllegalAccessException e)
        {
            String simpleName = objectClass.getSimpleName();
            throw new UncheckedTokenBindingException("IllegalAccessException trying to invoked a method on " + simpleName, e);
        }
        catch (InvocationTargetException e)
        {
            String simpleName = objectClass.getSimpleName();
            Throwable targetException = e.getTargetException();
            throw new UncheckedTokenBindingException("Exception thrown by an invoked method on " + simpleName, targetException);
        }
    }

    public void setSupportedTokenBindingKeyParams(SSLSocket sslSocket, byte[] supportedTokenBindingKeyParams) throws NoSuchMethodException
    {
        setSupportedTokenBindingKeyParams(sslSocket, sslSocket.getClass(), supportedTokenBindingKeyParams);
    }

    public void setSupportedTokenBindingKeyParams(SSLEngine engine, byte[] supportedTokenBindingKeyParams) throws NoSuchMethodException
    {
        setSupportedTokenBindingKeyParams(engine, engine.getClass(), supportedTokenBindingKeyParams);
    }

    void setSupportedTokenBindingKeyParams(Object object, Class<?> objectClass, byte[] supported) throws NoSuchMethodException
    {
        try
        {
            Method supportedKeyParamsMethod = objectClass.getMethod("setSupportedTokenBindingKeyParams", byte[].class);
            supportedKeyParamsMethod.invoke(object, (Object) supported);
        }
        catch (IllegalAccessException e)
        {
            String simpleName = objectClass.getSimpleName();
            throw new UncheckedTokenBindingException("IllegalAccessException trying to invoked a method on " + simpleName, e);
        }
        catch (InvocationTargetException e)
        {
            String simpleName = objectClass.getSimpleName();
            Throwable targetException = e.getTargetException();
            throw new UncheckedTokenBindingException("Exception thrown by an invoked method on " + simpleName, targetException);
        }

    }

    public static class TlsTbInfo
    {
        private Byte negotiatedKeyParamsId;
        private byte[] ekm;

        TlsTbInfo(Byte negotiatedKeyParamsId, byte[] ekm)
        {
            this.negotiatedKeyParamsId = negotiatedKeyParamsId;
            this.ekm = ekm;
        }

        public Byte getNegotiatedKeyParamsId()
        {
            return negotiatedKeyParamsId;
        }

        public byte[] getEkm()
        {
            return ekm;
        }
    }
}
