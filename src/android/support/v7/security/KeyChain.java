package android.support.v7.security;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.OptionalDataException;
import java.io.StreamCorruptedException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PrivilegedExceptionAction;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import android.annotation.TargetApi;
import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.support.v7.security.impl.CertChooser;
import android.support.v7.security.impl.CertInstaller;
import android.support.v7.security.impl.Credentials;
import android.support.v7.security.impl.HiddenKeyStore;
import android.support.v7.security.impl.HiddenKeyStore.State;
import android.util.Log;

/**
 * @see android.security.KeyChain
 * @author pprados
 *
 */
@TargetApi(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
public class KeyChain
{
	public static final String TAG="KeyChain";
	/** @see android.security.KeyChain#EXTRA_NAME */
	public static final String EXTRA_NAME = "name"; 	
	/** @see android.security.KeyChain#EXTRA_PKCS12 */
	public static final String EXTRA_PKCS12 = "PKCS12";
	// Not implemented
    // public static final String EXTRA_CERTIFICATE = "CERT";

    // Not implemented
    //public static final String EXTRA_SENDER = "sender";
	// 7>=
	private static final boolean PRE_ICS=false; // Flag for simulate old version

	// Keypair algorithm.
    private static final String KEYPAIR_ALGORITHM							="RSA";
    
    private final Context mContext;
	// Cached values
	protected String mLastAlias;
	protected KeyStore mLastKeyStore;

	/** @hide */
	/*private*/public HiddenKeyStore mHiddenKeyStore;
	
	//private KeyStore mKs ;
	public KeyChain(Context context)
	{
		mContext=context;

		if (!PRE_ICS && Build.VERSION.SDK_INT>=Build.VERSION_CODES.ICE_CREAM_SANDWICH)
		{
		}
		else
			mHiddenKeyStore=HiddenKeyStore.getInstance();
	}

	/**
	 * Return true if the KeyStore is unlocked.
	 * @return Keystore lock state.
	 */
	public boolean isUnLocked()
	{
		if (!PRE_ICS && Build.VERSION.SDK_INT>=Build.VERSION_CODES.ICE_CREAM_SANDWICH)
		{
			return true;
		}
		else
		{
			if (mHiddenKeyStore==null) return true;
			return (mHiddenKeyStore.state()==State.UNLOCKED);
		}
	}
	/**
	 * Unlock the keystore.
	 * 
	 * @param context The current activity.
	 */
	public void unlock(Activity context)
	{
		if (mHiddenKeyStore==null) return;
		if (mHiddenKeyStore.state()!=State.UNLOCKED)
		{
			try
			{
				if (Build.VERSION.SDK_INT < Build.VERSION_CODES.HONEYCOMB)
				{
					context.startActivity(new Intent("android.credentials.UNLOCK"));
				}
				else
				{
					context.startActivity(new Intent("com.android.credentials.UNLOCK"));
				}
			}
			catch (ActivityNotFoundException e)
			{
				throw new Error(e);
			}
		}
	}
	/**
	 * With emulation, can install only certificate from EXTRA_PKCS12.
	 * 
	 * @return Intent to extends with extras.
	 * @see android.security.KeyChain#createInstallIntent()
	 */
	public Intent createInstallIntent()
	{
		if (!PRE_ICS && Build.VERSION.SDK_INT >= Build.VERSION_CODES.ICE_CREAM_SANDWICH)
			return android.security.KeyChain.createInstallIntent();
		else
		{
			Intent intent=new Intent();
			intent.setComponent(new ComponentName(mContext,CertInstaller.class));
			int id=CertInstaller.sId++;
			CertInstaller.sKeyChains.append(id, this);
			intent.putExtra(CertInstaller.EXTRA_KEYCHAIN, id);
			return intent;
		}
	}
	
	/**
	 * 
	 * @see android.security.KeyChain#getCertificateChain(Context, String)
	 */
	public X509Certificate[] getCertificateChain(final Context context,final String alias) throws InterruptedException, KeyChainException
	{
		if (!PRE_ICS && Build.VERSION.SDK_INT>=Build.VERSION_CODES.ICE_CREAM_SANDWICH)
		{
			return new PrivilegedExceptionAction<X509Certificate[]>()
			{

				@Override
				public X509Certificate[] run() throws InterruptedException, KeyChainException
				{
					try
					{
						return android.security.KeyChain.getCertificateChain(context, alias);
					}
					catch (android.security.KeyChainException e)
					{
						throw new KeyChainException(e);
					}
				}
			}.run();
		}
		else
		{
			try
			{
				byte[] buf=mHiddenKeyStore.get(Credentials.USER_CERTIFICATE+alias);
				return (X509Certificate[])new ObjectInputStream(new ByteArrayInputStream(buf)).readObject();
			}
			catch (OptionalDataException e)
			{
				Log.i(TAG,"Impossible to read certificate",e);
				return null;
			}
			catch (StreamCorruptedException e)
			{
				Log.i(TAG,"Impossible to read certificate",e);
				return null;
			}
			catch (ClassNotFoundException e)
			{
				Log.i(TAG,"Impossible to read certificate",e);
				return null;
			}
			catch (IOException e)
			{
				Log.i(TAG,"Impossible to read certificate",e);
				return null;
			}
		}
	}
	
	/**
	 * 
	 * @see android.security.KeyChain#getPrivateKey(Context, String)
	 */
	public PrivateKey getPrivateKey(final Context context,final String alias) throws KeyChainException, InterruptedException
	{
		if (!PRE_ICS && Build.VERSION.SDK_INT>=Build.VERSION_CODES.ICE_CREAM_SANDWICH)
		{
			return new PrivilegedExceptionAction<PrivateKey>()
				{
					@Override
					public PrivateKey run() throws InterruptedException, KeyChainException
					{
						try
						{
							return android.security.KeyChain.getPrivateKey(context, alias);
						}
						catch (android.security.KeyChainException e)
						{
							throw new KeyChainException(e);
						}
					}
				}.run();
		}
		else
		{
			try
			{
				byte[] keyByte=mHiddenKeyStore.get(Credentials.USER_PRIVATE_KEY+alias);
				KeyFactory rsaFactory = KeyFactory.getInstance(KEYPAIR_ALGORITHM);
				PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(keyByte);
				return rsaFactory.generatePrivate(privKeySpec);
			}
			catch (NoSuchAlgorithmException e)
			{
				Log.i(TAG,"Impossible to extract private key",e);
				return null;
			}
			catch (InvalidKeySpecException e)
			{
				Log.i(TAG,"Impossible to extract private key",e);
				return null;
			}
		}
	}

	/**
	 * 
	 * @see android.security.KeyChain#choosePrivateKeyAlias(Activity, android.security.KeyChainAliasCallback, String[], Principal[], String, int, String)
	 */
	public void choosePrivateKeyAlias(
			final Activity activity,
			final KeyChainCallBack response,
			final String[] keyTypes,
			final Principal[] issues,
			final String host,
			final int port,
			final String alias
			)
	{
		if (!PRE_ICS && Build.VERSION.SDK_INT>=Build.VERSION_CODES.ICE_CREAM_SANDWICH)
		{
			new PrivilegedExceptionAction<Void>()
					{
						@Override
						public Void run()
						{
							android.security.KeyChain.choosePrivateKeyAlias(activity,
									new android.security.KeyChainAliasCallback()
									{
										@Override
										public void alias(String alias)
										{
											response.alias(alias);
										}
										
									},keyTypes,issues,host,port,alias);
							return null;
						}
					}.run();
		}
		else
		{
			if (activity == null) throw new NullPointerException("activity == null");
			if (response == null) throw new NullPointerException("response == null");
			
			Intent intent = new Intent(activity,CertChooser.class);
			CertChooser.addResponse(intent,response);
			intent.putExtra(CertInstaller.EXTRA_HOST, host);
			intent.putExtra(CertInstaller.EXTRA_PORT, port);
			intent.putExtra(CertInstaller.EXTRA_ALIAS, alias);
			activity.startActivity(intent);
		}
		
	}
	
}
