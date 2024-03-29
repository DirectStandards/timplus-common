package org.directtruststandards.timplus.common.crypto.impl;


import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;


import java.security.KeyStore.Entry;
import java.security.KeyStore.SecretKeyEntry;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.directtruststandards.timplus.common.crypto.CryptoUtils;
import org.junit.jupiter.api.Test;

public class BootstrappedKeyStoreProtectionManager_constructTest 
{
	static
	{
		CryptoUtils.registerJCEProviders();
	}
	
	@Test
	public void testConstructBootstrappedKeyStoreProtectionManager_defaultContstructor() throws Exception
	{
		final BootstrappedKeyStoreProtectionManager mgr = new BootstrappedKeyStoreProtectionManager();
		assertNotNull(mgr.keyEntries);
		assertTrue(mgr.keyEntries.isEmpty());
		assertNull(mgr.keyStoreProtectionKey);
		assertNull(mgr.privateKeyProtectionKey);
	}
	
	@Test
	public void testConstructBootstrappedKeyStoreProtectionManager_keysAsString() throws Exception
	{
		final BootstrappedKeyStoreProtectionManager mgr = new BootstrappedKeyStoreProtectionManager("Hello", "There");
		assertNotNull(mgr.keyEntries);
		assertFalse(mgr.keyEntries.isEmpty());
		assertEquals(2, mgr.keyEntries.size());
		assertNotNull(mgr.keyStoreProtectionKey);
		assertNotNull(mgr.privateKeyProtectionKey);
	}
	
	@Test
	public void testConstructBootstrappedKeyStoreProtectionManager_keysAsStringAndEntries() throws Exception
	{
		
		final Map<String, Entry> keyEntries = new HashMap<String, Entry>();
		final SecretKey key = new SecretKeySpec("Something".getBytes(), "");
		keyEntries.put("ThisEntry", new SecretKeyEntry((SecretKey)key));
		
		final BootstrappedKeyStoreProtectionManager mgr = new BootstrappedKeyStoreProtectionManager("Hello", "There", keyEntries);
		assertNotNull(mgr.keyEntries);
		assertEquals(3, mgr.keyEntries.size());
		assertNotNull(mgr.keyStoreProtectionKey);
		assertNotNull(mgr.privateKeyProtectionKey);
	}	
}
