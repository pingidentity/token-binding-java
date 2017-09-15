package b_c.unbearable.messages.https;

import javax.net.ssl.SSLEngine;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 *
 */
public class UnbearableJsseAdapter
{
    public TlsTbInfo getTbInfo(SSLEngine engine) throws TBException, NoSuchMethodException, IllegalAccessException
    {
        Class<? extends SSLEngine> engineClass = engine.getClass();
        try
        {
            Byte negotiatedKeyParamsId;
            byte[] ekm;
            Method tbKeyParamsMethod = engineClass.getMethod("getTokenBindingKeyParamsId");
            negotiatedKeyParamsId = (Byte)tbKeyParamsMethod.invoke(engine);

            Method ekmMethod = engineClass.getMethod("exportKeyingMaterial", String.class, int.class);
            Object invoked = ekmMethod.invoke(engine, "EXPORTER-Token-Binding", 32);
            ekm = (byte[]) invoked;
            return new TlsTbInfo(negotiatedKeyParamsId, ekm);
        }
        catch (InvocationTargetException e)
        {
            throw new TBException("Exception thrown by an invoked method on SSLEngine.", e.getTargetException());
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
