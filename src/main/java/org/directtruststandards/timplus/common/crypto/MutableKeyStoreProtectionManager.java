package org.directtruststandards.timplus.common.crypto;

import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.Entry;

import org.directtruststandards.timplus.common.crypto.exceptions.CryptoException;

/**
 * Interface for setting and clearing the secret keys for keystore and private key protection.  This
 * interface is implemented by stores that allow manipulation of the key material.
 * <p>
 * This interface assumes that key material is generated outside of the key store manager.
 * @author Greg Meyer
 * @since 1.0
 */
public interface MutableKeyStoreProtectionManager extends KeyStoreProtectionManager
{
	/**
	 * Sets key used to protect the private key as a Key object.
	 * @param key The key used to protect private keys.
	 * @throws CryptoException
	 */
	public void setPrivateKeyProtectionKey(Key key) throws CryptoException;
	
	/**
	 * Sets the key used to protect the private key as a byte array.
	 * @param key The key used to protect private keys.
	 * @throws CryptoException
	 */
	public void setPrivateKeyProtectionKeyAsBytes(byte[] key) throws CryptoException;
	
	/**
	 * Sets the key used to protect the private key as a string.  This is useful when pass phrases
	 * are generated by a plain text tool.
	 * @param key The key used to protect private keys.
	 * @throws CryptoException
	 */	
	public void setPrivateKeyProtectionKeyAsString(String key) throws CryptoException;
	
	/**
	 * Clears the key use to protect the private key.  Some implementations require that the
	 * key be cleared before a new value can be set.  For deterministic results, you should always
	 * clear the key before setting a new value.
	 * @throws CryptoException
	 */
	public void clearPrivateKeyProtectionKey() throws CryptoException;
	
	/**
	 * Sets key used to protect the key store as a Key object.
	 * @param key The key used to protect the key store.
	 * @throws CryptoException
	 */
	public void setKeyStoreProtectionKey(Key key) throws CryptoException;
	
	/**
	 * Sets key used to protect the key store as a byte array.
	 * @param key The key used to protect the key store.
	 * @throws CryptoException
	 */	
	public void setKeyStoreProtectionKeyAsBytes(byte[] key) throws CryptoException;	
	
	/**
	 * Sets key used to protect the key store as a string.  This is useful when pass phrases
	 * are generated by a plain text tool.
	 * @param key The key used to protect the key store.
	 * @throws CryptoException
	 */	
	public void setKeyStoreProtectionKeyAsString(String key) throws CryptoException;		

	/**
	 * Clears the key use to protect the key store.  Some implementations require that the
	 * key be cleared before a new value can be set.  For deterministic results, you should always
	 * clear the key before setting a new value.
	 * @throws CryptoException
	 */
	public void clearKeyStoreProtectionKey() throws CryptoException;
	
	/**
	 * Generic method to set an arbitrary key.
	 * @param alias Alias of the key that will be set.
	 * @param key The key that will be set.
	 * @throws CryptoException
	 */
	public void setKey(String alias, Key key) throws CryptoException;

	/**
	 * Generic method to clear an arbitrary key.
	 * @param alias Alias of the key that will be cleared.
	 * @throws CryptoException
	 */
	public void clearKey(String alias) throws CryptoException;
	
	/**
	 * Generic method to set an arbitrary entry.
	 * @param alias Alias of the entry that will be set.
	 * @param entry The entry that will be set.
	 * @throws CryptoException
	 */
	public void setEntry(String alias, Entry entry) throws CryptoException;

	/**
	 * Generic method to clear an arbitrary entry.
	 * @param alias Alias of the entry that will be cleared.
	 * @throws CryptoException
	 */
	public void clearEntry(String alias) throws CryptoException;
	
	
	/**
	 * Gets the underlying KeyStore object.
	 * @return The KeyStore object backing the protection manager.
	 */
	public KeyStore getKS();
}
