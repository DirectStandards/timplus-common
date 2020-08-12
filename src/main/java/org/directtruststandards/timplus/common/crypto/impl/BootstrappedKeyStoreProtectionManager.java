package org.directtruststandards.timplus.common.crypto.impl;

import java.security.Key;
import java.security.KeyStore.Entry;
import java.security.KeyStore.SecretKeyEntry;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.directtruststandards.timplus.common.crypto.KeyStoreProtectionManager;
import org.directtruststandards.timplus.common.crypto.WrappableKeyProtectionManager;
import org.directtruststandards.timplus.common.crypto.exceptions.CryptoException;

/**
 * Implementation of a key store manager where the protection keys are provided as injected parameters.  This class is useful if the 
 * pass phrases or keys are stored in configuration files and can be provided as declarative config statements.
 * @author Greg Meyer
 * @since 1.0
 */
public class BootstrappedKeyStoreProtectionManager implements KeyStoreProtectionManager, WrappableKeyProtectionManager
{
	public final static String PrivKeyProtKey = "PrivKeyProtKey";
	public final static String KeyStoreProtKey = "KeyStoreProtKey";
	
	protected Key keyStoreProtectionKey;
	protected Key privateKeyProtectionKey;
	protected Map<String, Entry> keyEntries;
	
	/**
	 * Empty constructore
	 */
	public BootstrappedKeyStoreProtectionManager ()
	{
		setKeyEntries(null);
	}
	
	/**
	 * Constructs a manager by providing the protection keys as strings.
	 * @param keyStoreProtectionKey The pass phrase that protects the key store as a whole.
	 * @param privateKeyProtectionKey The pass phrase that protects the private keys in the key store.
	 */
	public BootstrappedKeyStoreProtectionManager (String keyStoreProtectionKey, String privateKeyProtectionKey) throws CryptoException 
	{
		setKeyEntries(null);
		setKeyStoreProtectionKey(keyStoreProtectionKey);
		setPrivateKeyProtectionKey(privateKeyProtectionKey);
	}
	
	/**
	 * Constructs a manager by providing the protection keys as strings and a collection of key entries
	 * @param keyStoreProtectionKey The pass phrase that protects the key store as a whole.
	 * @param privateKeyProtectionKey The pass phrase that protects the private keys in the key store.
	 * @param entries Key entries
	 */
	public BootstrappedKeyStoreProtectionManager (String keyStoreProtectionKey, String privateKeyProtectionKey,
			Map<String, Entry> entries) throws CryptoException 
	{
		setKeyEntries(entries);
		setKeyStoreProtectionKey(keyStoreProtectionKey);
		setPrivateKeyProtectionKey(privateKeyProtectionKey);
	}
	
	/**
	 * Sets the pass phrase that protects the key store as a whole as a String.
	 * @param keyStoreProtectionKey The pass phrase that protects the key store as a whole as a String.
	 */
	public void setKeyStoreProtectionKey(String keyStoreProtectionKey) throws CryptoException 
	{
		this.keyStoreProtectionKey = buildSecretKeyFromString(keyStoreProtectionKey);
		keyEntries.put(KeyStoreProtKey, new SecretKeyEntry((SecretKey)this.keyStoreProtectionKey));
	}
	
	/**
	 * Sets the pass phrase that protects the private keys in the key store as a String.
	 * @param privateKeyProtectionKey The pass phrase that protects the private keys in the key store as a String.
	 */
	public void setPrivateKeyProtectionKey(String privateKeyProtectionKey) throws CryptoException 
	{
		this.privateKeyProtectionKey = buildSecretKeyFromString(privateKeyProtectionKey);
		keyEntries.put(PrivKeyProtKey, new SecretKeyEntry((SecretKey)this.privateKeyProtectionKey));
	}
	
	/**
	 * Sets the key entries.
	 * @param entries The key entries
	 */
	public void setKeyEntries(Map<String, Entry> entries) 
	{
		this.keyEntries = (entries == null) ? new HashMap<String, Entry>() : new HashMap<String, Entry>(entries);
		// add the static entries
		if (this.keyStoreProtectionKey != null)
			keyEntries.put(PrivKeyProtKey, new SecretKeyEntry((SecretKey)this.keyStoreProtectionKey));
		if (this.keyStoreProtectionKey != null)
			keyEntries.put(KeyStoreProtKey, new SecretKeyEntry((SecretKey)this.privateKeyProtectionKey));
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Key getPrivateKeyProtectionKey() throws CryptoException 
	{
		return privateKeyProtectionKey;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Key getKeyStoreProtectionKey() throws CryptoException 
	{
		return keyStoreProtectionKey;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Map<String, Key> getAllKeys() throws CryptoException 
	{
		final Map<String, Key> keys = new HashMap<String, Key>();
		for (Map.Entry<String, Entry> keyEntry : this.keyEntries.entrySet())
			if (keyEntry.getValue() instanceof SecretKeyEntry)
				keys.put(keyEntry.getKey(), ((SecretKeyEntry)keyEntry.getValue()).getSecretKey());
	
		return keys;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Key getKey(String keyName) throws CryptoException
	{
		final Entry keyEntry = getEntry(keyName);
		if (keyEntry != null && keyEntry instanceof SecretKeyEntry)
			return ((SecretKeyEntry)keyEntry).getSecretKey();

		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Map<String, Entry> getAllEntries() throws CryptoException 
	{
		return Collections.unmodifiableMap(keyEntries);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Entry getEntry(String entryName) throws CryptoException 
	{
		return this.keyEntries.get(entryName);
	}
	
	/**
	 * {@inheritDoc}}
	 */
	@Override
	public byte[] wrapWithSecretKey(SecretKey kek, Key keyToWrap) throws CryptoException 
	{
		final IvParameterSpec iv = new IvParameterSpec(AbstractPKCS11TokenKeyStoreProtectionManager.IV_BYTES);
		try
		{
			final Cipher wrapCipher = Cipher.getInstance(AbstractPKCS11TokenKeyStoreProtectionManager.WRAP_ALGO);
			wrapCipher.init(Cipher.WRAP_MODE, kek, iv);

			return wrapCipher.wrap(keyToWrap);
		}
		catch (Exception e)
		{
			throw new CryptoException("Failed to wrap key: " + e.getMessage(), e);
		}

	}

	/**
	 * {@inheritDoc}}
	 */
	@Override
	public Key unwrapWithSecretKey(SecretKey kek, byte[] wrappedData, String keyAlg, int keyType) throws CryptoException 
	{
		final IvParameterSpec iv = new IvParameterSpec(AbstractPKCS11TokenKeyStoreProtectionManager.IV_BYTES);
		try
		{
			final Cipher unwrapCipher = Cipher.getInstance(AbstractPKCS11TokenKeyStoreProtectionManager.WRAP_ALGO);
			unwrapCipher.init(Cipher.UNWRAP_MODE, kek, iv);
	
			return unwrapCipher.unwrap(wrappedData, keyAlg, keyType);
		}
		catch (Exception e)
		{
			throw new CryptoException("Failed to unwrap key: " + e.getMessage(), e);
		}
	}
	
	protected Key buildSecretKeyFromString(String data) throws CryptoException 
	{
		byte[] salt = {(byte)0x83, (byte)0x95, (byte)0xa9, (byte)0xd8};
		
        final PBEKeySpec keySpec = new PBEKeySpec(data.toCharArray(), salt, 65536, 128);
        
        try
        {
        	final SecretKeyFactory keyFac = SecretKeyFactory.getInstance("pbewithsha256and128bitaes-cbc-bc", "BC");
        	SecretKey tmp = keyFac.generateSecret(keySpec);
        	
        	return new SecretKeySpec(tmp.getEncoded(), "AES");
        }
        catch (Exception e)
        {
        	throw new CryptoException("Could not create secret key for password.", e);
        }
      
	}
	
}
