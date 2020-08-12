package org.directtruststandards.timplus.common.crypto;

import java.security.Key;
import java.security.KeyStore.Entry;
import java.util.Map;

import org.directtruststandards.timplus.common.crypto.exceptions.CryptoException;

/**
 * Interface definition for accessing key store pass phrases.  PKCS12 keystores generally have two layers of protection with each being options:
 * <br>
 * <ul>
 * <li>Pass phrase protection for the entire key store.</li>
 * <li>Pass phrase protection for private keys associated with a public key</li>
 * <br>
 * This interface assumes that all private keys are stores with the same pass phrase.  Pass phrases may stored in a multitude of mediums such as protected files,
 * databases, or PKCS11 tokens.
 * @author Greg Meyer
 * @since 1.0
 *
 */
public interface KeyStoreProtectionManager 
{
	/**
	 * Gets the key protecting the key store as a whole.
	 * @return The key protecting the key store as a whole.
	 * @throws CryptoException
	 */
	public Key getPrivateKeyProtectionKey() throws CryptoException;
	
	/**
	 * Gets the key protecting private keys in the key store.
	 * @return The key protecting private keys in the key store.
	 * @throws CryptoException
	 */
	public Key getKeyStoreProtectionKey() throws CryptoException;
	
	/**
	 * Gets a Map of all keys managed by the token.
	 * @return Returns a map of all keys in the token.  The mapping is string alias to the key.
	 * @throws CryptoException
	 */
	public Map<String, Key> getAllKeys() throws CryptoException;
	
	/**
	 * Gets a specific key by name.
	 * @param keyName The name of the key to retrieve.  Returns null if the key doesn't exist.
	 * @return They key specified by the name. 
	 * @throws CryptoException
	 */
	public Key getKey(String keyName) throws CryptoException;
	
	/**
	 * Gets a Map of all entries managed by the token.
	 * @return Returns a map of all entries in the token.  The mapping is a string alias to the entry.
	 * @throws CryptoException
	 */
	public Map<String, Entry> getAllEntries() throws CryptoException;
	
	/**
	 * Gets a specific entry by name
	 * @param entryName The name of the entry to retrieve.  Returns null if the entry doesn't exist.
	 * @return They entry specified by the name.
	 * @throws CryptoException
	 */
	public Entry getEntry(String entryName) throws CryptoException;
}
