package org.directtruststandards.timplus.common.crypto;


import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.Provider;
import java.security.Security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility functions for searching for certificates.
 * @author Greg Meyer
 * 
 * @since 1.0
 */
public class CryptoUtils 
{	
	private static final String DEFAULT_JCE_PROVIDER_CLASS = "org.bouncycastle.jce.provider.BouncyCastleProvider";

	private static final String DEFAULT_SENSITIVE_JCE_PROVIDER_CLASS = "org.bouncycastle.jce.provider.BouncyCastleProvider";
	
	
	private static final Logger LOGGER = LoggerFactory.getLogger(CryptoUtils.class);
	
	/**
	 * Typically JCE providers are registered through JVM properties files or statically calling {@link Security#addProvider(Provider)}.  The method 
	 * allows for configuration of JCE Providers through the {@link OptionsManager} classes.  This method iterates through a comma delimited set of providers,
	 * dynamically loads the provider class, and and registered each one if it has not already been registered.
	 * <p>
	 * If a provider is not configured via the {@link OptionsManager}, then the default BouncyCastle provider is registered (if it has not been
	 * already registered).
	 */
	public static void registerJCEProviders()
	{
		// registering the default JCE providers

		String[] providerClasses = new String[] {DEFAULT_JCE_PROVIDER_CLASS};

		// register the provider classes
		for (String providerClass : providerClasses)
		{
			try
			{
				final Class<?> providerClazz = CryptoUtils.class.getClassLoader().loadClass(providerClass);
				final Provider provider = Provider.class.cast(providerClazz.newInstance());
				
				// check to see if the provider is already registered
				if (Security.getProvider(provider.getName()) == null)
					Security.addProvider(provider);
				
			}
			catch (Exception e)
			{
				throw new IllegalStateException("Could not load and/or register JCE provider " + providerClass, e);
			}
		}
		
		// registering the default sensitive JCE providers
		providerClasses = new String[] {DEFAULT_SENSITIVE_JCE_PROVIDER_CLASS};


		// register the provider classes
		for (String providerClass : providerClasses)
		{
			try
			{
				
				Provider provider = null;
				Class<?> providerClazz = null;
				// check to see if the provider class string has parameters
				final String provParams[] = providerClass.split(";");
				if (provParams.length > 1)
				{
					providerClazz = CryptoUtils.class.getClassLoader().loadClass(provParams[0]);
					try
					{
						@SuppressWarnings("unchecked")
						Constructor<Provider> constr = Constructor.class.cast(providerClazz.getConstructor(String.class));
						provider = constr.newInstance(provParams[1]);
					}
					catch (InvocationTargetException e)
					{
						
						if (e.getTargetException() instanceof IllegalStateException)
						{
							LOGGER.warn("Could not create a JCE Provider with the specific parameter: " + provParams[1], e);
						}
						else
							LOGGER.warn("JCE Provider param  " + provParams[1] + " provided but not supported by JCE Provider implementation:" + e.getMessage(), e);
					}
				}
				else
				{
					providerClazz = CryptoUtils.class.getClassLoader().loadClass(providerClass);
				}
				
				if (provider == null)
				{
					provider = Provider.class.cast(providerClazz.newInstance());	
				}
				
				// check to see if the provider is already registered
				if (Security.getProvider(provider.getName()) == null)
					Security.addProvider(provider);
				
			}
			catch (Exception e)
			{
				throw new IllegalStateException("Could not load and/or register sensitive JCE provider " + providerClass, e);
			}
		}		
	}
	
	public static void registerJCEProvider(Provider provider)
	{
		// check to see if the provider is already registered
		if (Security.getProvider(provider.getName()) == null)
			Security.addProvider(provider);
	}
}
