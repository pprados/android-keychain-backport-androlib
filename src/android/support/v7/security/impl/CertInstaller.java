package android.support.v7.security.impl;

import static android.support.v7.security.KeyChain.TAG;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v7.security.KeyChain;
import android.support.v7.security.R;
import android.text.Html;
import android.text.TextUtils;
import android.util.Log;
import android.util.SparseArray;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

public class CertInstaller extends Activity
{
	public static final String			EXTRA_ALIAS				= "alias";

	public static final String			EXTRA_HOST				= "host";

	public static final String			EXTRA_PORT				= "port";

	private static final int			PKCS12_PASSWORD_DIALOG	= 1;

	private static final int			NAME_CREDENTIAL_DIALOG	= 2;

	private static final int			PROGRESS_BAR_DIALOG		= 3;

	private String						mName;

	private String						mAlias;

	private String						mPassword;

	private String						mHost;

	private String						mPort;

	private byte[]						mPkcs12;

	public static final String			EXTRA_KEYCHAIN			= "keychain";

	public static int					sId						= 0;

	public static SparseArray<KeyChain>	sKeyChains				= new SparseArray<KeyChain>();

	private KeyChain					mKeyChain;

	private PrivateKeyEntry				mKeyEntry;

	@Override
	protected void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);
		final Intent intent = getIntent();

		mName = intent.getStringExtra(KeyChain.EXTRA_NAME);
		String aliastemp = intent.getStringExtra(EXTRA_ALIAS);
		if (aliastemp == null)
			aliastemp = mName;
		mAlias = aliastemp;
		mHost = intent.getStringExtra(EXTRA_HOST);
		mPort = intent.getStringExtra(EXTRA_PORT);
		mPkcs12 = intent.getByteArrayExtra(KeyChain.EXTRA_PKCS12);
		int id = intent.getIntExtra(EXTRA_KEYCHAIN, -1);
		mKeyChain = sKeyChains.get(id);
		sKeyChains.delete(id);
		showDialog(PKCS12_PASSWORD_DIALOG);
	}

	/**
	 * Install certificate in KeyStore with the user password.
	 */
	private void decodeCert()
	{
		if (mPkcs12 != null)
		{
			new AsyncTask<Void, Void, Integer>()
			{
				@Override
				protected void onPreExecute()
				{
					removeDialog(PKCS12_PASSWORD_DIALOG);
					showDialog(PROGRESS_BAR_DIALOG);
				}

				@Override
				protected Integer doInBackground(Void... params)
				{
					try
					{
						if (!extractPkcs12Internal(mName, mPkcs12, mPassword))
							return R.string.keystore_error;
						Log.d(TAG, "Certificate " + mAlias + " installed");
					}
					catch (Exception e)
					{
						return R.string.password_error;
					}
					return -1;
				}

				@Override
				protected void onPostExecute(Integer result)
				{
					removeDialog(PROGRESS_BAR_DIALOG);
					if (result != -1)
					{
						toastErrorAndFinish(result);
					}
					else
					{
						showDialog(NAME_CREDENTIAL_DIALOG);
					}
				}
			}.execute();
		}
	}

	@Override
	protected Dialog onCreateDialog(int dialogId)
	{
		switch (dialogId)
		{
			case PKCS12_PASSWORD_DIALOG:
				return createPkcs12PasswordDialog();

			case NAME_CREDENTIAL_DIALOG:
				return createNameCredentialDialog();
			case PROGRESS_BAR_DIALOG:
				ProgressDialog dialog = new ProgressDialog(this);
				dialog.setMessage(getString(R.string.extracting_pkcs12));
				dialog.setIndeterminate(true);
				dialog.setCancelable(false);
				return dialog;

			default:
				return null;
		}
	}

	private Dialog createPkcs12PasswordDialog()
	{
		final View view = View.inflate(this, R.layout.password_dialog, null);
		String title = mName;
		title = TextUtils.isEmpty(title) ? getString(R.string.pkcs12_password_dialog_title)
				: getString(R.string.pkcs12_file_password_dialog_title, title);
		Dialog d = new AlertDialog.Builder(this).setView(view).setTitle(title)
				.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener()
				{
					@Override
					public void onClick(DialogInterface dialog, int id)
					{
						mPassword = ((TextView) view.findViewById(R.id.credential_password))
								.getText().toString();
						InputMethodManager imm = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
						imm.hideSoftInputFromWindow(view.getWindowToken(), 0);
						decodeCert();
					}
				}).setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener()
				{
					@Override
					public void onClick(DialogInterface dialog, int id)
					{
						toastErrorAndFinish(R.string.cert_not_saved);
					}
				}).create();
		d.setOnCancelListener(new DialogInterface.OnCancelListener()
		{
			@Override
			public void onCancel(DialogInterface dialog)
			{
				toastErrorAndFinish(R.string.cert_not_saved);
			}
		});
		return d;
	}

	private Dialog createNameCredentialDialog()
	{
		ViewGroup view = (ViewGroup) View.inflate(this, R.layout.name_credential_dialog, null);
		// mView.setView(view);
		// if (mView.getHasEmptyError())
		// {
		// mView.showError(R.string.name_empty_error);
		// mView.setHasEmptyError(false);
		// }
		((TextView) view.findViewById(R.id.credential_info)).setText(getDescription());
		final EditText nameInput = (EditText) view.findViewById(R.id.credential_name);
		nameInput.setText(getDefaultName());
		nameInput.selectAll();
		Dialog d = new AlertDialog.Builder(this).setView(view)
				.setTitle(R.string.name_credential_dialog_title)
				.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener()
				{
					@Override
					public void onClick(DialogInterface dialog, int id)
					{
						String name = nameInput.getText().toString();
						if (TextUtils.isEmpty(name))
						{
							removeDialog(NAME_CREDENTIAL_DIALOG);
							showDialog(NAME_CREDENTIAL_DIALOG);
						}
						else
						{
							removeDialog(NAME_CREDENTIAL_DIALOG);
							mName = name;
							installCert();
						}
					}

					private void installCert()
					{
						setKeyStoreEntry(mName, mKeyEntry);
						Toast.makeText(CertInstaller.this,
								getString(R.string.cert_is_added, mName), Toast.LENGTH_LONG).show();
						finish();
					}
				}).setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener()
				{
					@Override
					public void onClick(DialogInterface dialog, int id)
					{
						toastErrorAndFinish(R.string.cert_not_saved);
					}
				}).create();
		d.setOnCancelListener(new DialogInterface.OnCancelListener()
		{
			@Override
			public void onCancel(DialogInterface dialog)
			{
				toastErrorAndFinish(R.string.cert_not_saved);
			}
		});
		return d;
	}

	private String getDefaultName()
	{
		String name = mName;
		if (TextUtils.isEmpty(name))
		{
			return null;
		}
		else
		{
			// remove the extension from the file name
			int index = name.lastIndexOf(".");
			if (index > 0)
				name = name.substring(0, index);
			return name;
		}
	}

	@Override
	protected void onResume()
	{
		super.onResume();
	}

	private void toastErrorAndFinish(int msgId)
	{
		Toast.makeText(this, msgId, Toast.LENGTH_SHORT).show();
		finish();
	}

	private boolean extractPkcs12Internal(String alias, byte[] pkcs12, String password)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
			UnrecoverableEntryException
	{
		java.security.KeyStore keystore = java.security.KeyStore.getInstance("PKCS12");
		PasswordProtection passwordProtection = new PasswordProtection(password.toCharArray());
		keystore.load(new ByteArrayInputStream(pkcs12), password.toCharArray());

		Enumeration<String> aliases = keystore.aliases();
		if (!aliases.hasMoreElements())
		{
			return false;
		}

		while (aliases.hasMoreElements())
		{
			String localAlias = aliases.nextElement();
			KeyStore.Entry entry = keystore.getEntry(localAlias, passwordProtection);
			Log.d(TAG, "extracted alias = " + localAlias + ", entry=" + entry.getClass());

			if (entry instanceof PrivateKeyEntry)
			{
				if (TextUtils.isEmpty(mName))
				{
					mName = localAlias;
				}
				mKeyEntry = (PrivateKeyEntry) entry;
				return true;
			}
		}
		return true;
	}

	private boolean setKeyStoreEntry(String alias, PrivateKeyEntry entry)
	{
		try
		{
			HiddenKeyStore keystore = mKeyChain.mHiddenKeyStore;
			if (!keystore.put(Credentials.USER_PRIVATE_KEY + alias, entry.getPrivateKey()
					.getEncoded()))
				return false;
			Certificate[] chain = entry.getCertificateChain();
			X509Certificate[] x509Chain = new X509Certificate[chain.length];
			for (int i = 0; i < chain.length; ++i)
				x509Chain[i] = (X509Certificate) chain[i];
			ByteArrayOutputStream buf = new ByteArrayOutputStream();
			new ObjectOutputStream(buf).writeObject(x509Chain);
			return keystore.put(Credentials.USER_CERTIFICATE + alias, buf.toByteArray());
		}
		catch (IOException e)
		{
			Log.i(TAG, "Impossible to store certificate", e);
			return false;
		}
	}

	CharSequence getDescription()
	{
		// TODO: create more descriptive string
		StringBuilder sb = new StringBuilder();
		String newline = "<br>";
		if (mKeyEntry != null)
		{
			sb.append(getString(R.string.one_userkey)).append(newline);
		}
		if (mKeyEntry != null)
		{
			sb.append(getString(R.string.one_usercrt)).append(newline);
		}

		int n = mKeyEntry.getCertificateChain().length;
		if (n > 0)
		{
			if (n == 1)
			{
				sb.append(getString(R.string.one_cacrt));
			}
			else
			{
				sb.append(getString(R.string.n_cacrts, n));
			}
		}
		return Html.fromHtml(sb.toString());
	}

}
