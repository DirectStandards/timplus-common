package org.directtruststandards.timplus.common.crypto.impl;

import org.directtruststandards.timplus.common.crypto.PKCS11Credential;

/**
 * Implementation of a PKCS11 credential where the pin is provided as an injected parameter.  This class is useful if the 
 * pin is stored in configuration files and can be provided as declarative config statements.
 * @author Greg Meyer
 * @since 1.0
 */
public class BootstrappedPKCS11Credential implements PKCS11Credential
{
	protected String pin;
	
	/**
	 * Empty constructor
	 */
	public BootstrappedPKCS11Credential()
	{

	}
	
	/**
	 * Constructor
	 * @param pin The PKCS11 pin used to login to the token
	 */
	public BootstrappedPKCS11Credential(String pin)
	{
		this.pin = pin;
	}

	/**
	 * Sets the pin 
	 * @param pin The PKCS11 pin used to login to the tokens
	 */
	public void setPin(String pin)
	{
		this.pin = pin;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public char[] getPIN() 
	{
		return pin.toCharArray();
	}
}
