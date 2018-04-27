package com.pingidentity.oss.unbearable;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

/**
 *
 */
public class JceProviderTestSupport
{

    public void runWithBouncyCastleProvider(RunnableTest test) throws Exception
    {
        BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
        boolean needBouncyCastle = true;

        boolean removeBouncyCastle = true;
        try
        {
            if (needBouncyCastle)
            {
                int position = Security.insertProviderAt(bouncyCastleProvider, 1);
                removeBouncyCastle = (position != -1);
            }

            test.runTest();
        }
        finally
        {
            if (needBouncyCastle)
            {
                if (removeBouncyCastle)
                {
                    Security.removeProvider(bouncyCastleProvider.getName());
                }
            }
        }
    }

    public static interface RunnableTest
    {
        public abstract void runTest() throws Exception;
    }
}
