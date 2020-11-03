package org.directtruststandards.timplus.common.crypto.impl;

import java.io.InputStream;
import java.security.KeyStore;

import javax.security.auth.callback.CallbackHandler;

import org.apache.commons.lang3.StringUtils;
import org.directtruststandards.timplus.common.crypto.exceptions.CryptoException;

/**
 * A more dynamic implementation than the StaticPKCS11TokenKeyStoreProtectionManager that allows for swap-able tokens and plug-able methods
 * for different logging into the token as described by the {@link javax.security.auth.callback.CallbackHandler} class.  Instances 
 * must provide a CallbackHander implementation for providing credential information.
 * @author Greg Meyer
 * @since 1.0
 */
/// CLOVER:OFF
public class DynamicPKCS11TokenKeyStoreProtectionManager extends AbstractPKCS11TokenKeyStoreProtectionManager
{
	protected CallbackHandler handler;
	protected KeyStore.Builder keyStoreBuilder;
	
	/**
	 * Default Constructor
	 * @throws CryptoException
	 */
	public DynamicPKCS11TokenKeyStoreProtectionManager() throws CryptoException
	{
		super();
	}
	
	/**
	 * Constructs the store with the aliases and a callback handler.
	 * @param keyStorePassPhraseAlias  The alias name of the key store key in the PKCS11 token.
	 * @param privateKeyPassPhraseAlias The alias name of the private key protection key in the PKCS11 token.
	 * @param handler A callback handler implementation used to obtain credential information.
	 * @throws CryptoException
	 */
	public DynamicPKCS11TokenKeyStoreProtectionManager(String keyStorePassPhraseAlias, String privateKeyPassPhraseAlias, CallbackHandler handler) throws CryptoException
	{
		this(keyStorePassPhraseAlias, keyStorePassPhraseAlias, handler, null, null);
	}
	
	public DynamicPKCS11TokenKeyStoreProtectionManager(String keyStorePassPhraseAlias, String privateKeyPassPhraseAlias, CallbackHandler handler, 
			String keyStoreType, InputStream inputStream) throws CryptoException
	{
		this.keyStorePassPhraseAlias = keyStorePassPhraseAlias;
		this.privateKeyPassPhraseAlias = privateKeyPassPhraseAlias;
		this.handler = handler;
		if (StringUtils.isEmpty(keyStoreType))
			this.keyStoreType = keyStoreType;
		else 
			this.keyStoreType = DEFAULT_KESTORE_TYPE;
		
		configureKeyStoreBuilder();
		
		initTokenStore();
	}
	
	/**
	 * Sets the callback handler used obtain credential information.
	 * @param handler The callback handler used obtain credential information.
	 */
	public void setCallbackHandler(CallbackHandler handler)
	{
		this.handler = handler;
		
		configureKeyStoreBuilder();
	}
	
	/**
	 * Configures the key store builder for creating token stores.
	 */
	protected void configureKeyStoreBuilder()
	{
		final KeyStore.CallbackHandlerProtection chp =
			    new KeyStore.CallbackHandlerProtection(handler);
		
		keyStoreBuilder = KeyStore.Builder.newInstance(keyStoreType, null, chp);
	}
	
	/**
	 * {@inheritDocs}
	 */
	public void initTokenStore() throws CryptoException
	{
		try
		{
			loadProvider();
			
			ks = keyStoreBuilder.getKeyStore();
			ks.load(keyStoreSource, null);
		}
		catch (Exception e)
		{
			throw new CryptoException("Error initializing PKCS11 token", e);
		}
	}
}
/// CLOVER:ON
