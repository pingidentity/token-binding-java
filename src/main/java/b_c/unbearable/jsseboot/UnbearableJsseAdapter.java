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
        return _getTbInfo(sslSocket);
    }

    public TlsTbInfo getTbInfo(SSLEngine engine) throws NoSuchMethodException
    {
        return _getTbInfo(engine);
    }

    TlsTbInfo _getTbInfo(Object object) throws NoSuchMethodException
    {
        Class<?> objectClass = object.getClass();
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
        _setSupportedTokenBindingKeyParams(sslSocket, supportedTokenBindingKeyParams);
    }

    public void setSupportedTokenBindingKeyParams(SSLEngine engine, byte[] supportedTokenBindingKeyParams) throws NoSuchMethodException
    {
        _setSupportedTokenBindingKeyParams(engine, supportedTokenBindingKeyParams);
    }

    void _setSupportedTokenBindingKeyParams(Object object, byte[] supported) throws NoSuchMethodException
    {
        Class<?> objectClass = object.getClass();
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
