package org.directtruststandards.timplus.common.crypto.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.directtruststandards.timplus.common.crypto.CryptoUtils;
import org.junit.Test;


public class BootstrappedKeyStoreProtectionManagerTest 
{
	static
	{
		CryptoUtils.registerJCEProviders();
	}
	
	@Test
	public void testGetSetKeysFromString() throws Exception
	{
		BootstrappedKeyStoreProtectionManager mgr = new BootstrappedKeyStoreProtectionManager();
		mgr.setKeyStoreProtectionKey("1234");
		mgr.setPrivateKeyProtectionKey("5678");
		
		assertNotNull(mgr.getKeyStoreProtectionKey());
		assertNotNull(mgr.getPrivateKeyProtectionKey().getEncoded());
	}	
	
	@Test
	public void testGetAllKeys() throws Exception
	{
		BootstrappedKeyStoreProtectionManager mgr = new BootstrappedKeyStoreProtectionManager();
		mgr.setKeyStoreProtectionKey("1234");
		mgr.setPrivateKeyProtectionKey("5678");
		
		final Map<String, Key> keys = mgr.getAllKeys();
		
		assertEquals(2, keys.size());
		
		Iterator<Entry<String, Key>> entryIter = keys.entrySet().iterator();
				
		Key key = entryIter.next().getValue();		
		assertNotNull(key);
		key = entryIter.next().getValue();	
		assertNotNull(key);
	}
	
	@Test
	public void testWrapUnwrapKey() throws Exception
	{
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		final KeyPair pair = keyPairGenerator.generateKeyPair();
		
		pair.getPrivate();
		
		final BootstrappedKeyStoreProtectionManager mgr = new BootstrappedKeyStoreProtectionManager();
		mgr.setKeyStoreProtectionKey("1234");
		mgr.setPrivateKeyProtectionKey("5678");
		
		byte[] wrappedKey = mgr.wrapWithSecretKey((SecretKey)mgr.getPrivateKeyProtectionKey(), pair.getPrivate());
		assertNotNull(wrappedKey);
		
		final Key unwrappedKey = mgr.unwrapWithSecretKey((SecretKey)mgr.getPrivateKeyProtectionKey(), wrappedKey, "RSA", Cipher.PRIVATE_KEY);
		
		assertEquals(unwrappedKey, pair.getPrivate());
	}
}
