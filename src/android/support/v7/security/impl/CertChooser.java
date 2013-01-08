package android.support.v7.security.impl;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v7.security.KeyChainCallBack;
import android.support.v7.security.R;
import android.util.SparseArray;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.BaseAdapter;
import android.widget.ListView;
import android.widget.RadioButton;
import android.widget.TextView;

public class CertChooser extends Activity
{
	public static final String						EXTRA_RESPONSE	= "response";

	private static SparseArray<KeyChainCallBack>	sCallBacks		= new SparseArray<KeyChainCallBack>();

	private static int								sCallBackId;

	// beware that some of these KeyStore operations such as saw and
	// get do file I/O in the remote keystore process and while they
	// do not cause StrictMode violations, they logically should not
	// be done on the UI thread.
	private final HiddenKeyStore					mKeyStore		= HiddenKeyStore.getInstance();

	private static class ViewHolder
	{
		TextView	mAliasTextView;

		TextView	mSubjectTextView;

		RadioButton	mRadioButton;
	}

	private void showCertChooserDialog()
	{
		new AliasLoader().execute();
	}

	private class AliasLoader extends AsyncTask<Void, Void, CertificateAdapter>
	{
		@Override
		protected CertificateAdapter doInBackground(Void... params)
		{
			String[] aliasArray = mKeyStore.saw(Credentials.USER_PRIVATE_KEY);
			List<String> aliasList = ((aliasArray == null) ? Collections.<String> emptyList()
					: Arrays.asList(aliasArray));
			Collections.sort(aliasList);
			return new CertificateAdapter(aliasList);
		}

		@Override
		protected void onPostExecute(CertificateAdapter adapter)
		{
			displayCertChooserDialog(adapter);
		}
	}

	private class CertificateAdapter extends BaseAdapter
	{
		private final List<String>	mAliases;

		private final List<String>	mSubjects	= new ArrayList<String>();

		private CertificateAdapter(List<String> aliases)
		{
			mAliases = aliases;
			mSubjects.addAll(Collections.nCopies(aliases.size(), (String) null));
		}

		@Override
		public int getCount()
		{
			return mAliases.size();
		}

		@Override
		public String getItem(int adapterPosition)
		{
			return mAliases.get(adapterPosition);
		}

		@Override
		public long getItemId(int adapterPosition)
		{
			return adapterPosition;
		}

		@Override
		public View getView(final int adapterPosition, View view, ViewGroup parent)
		{
			ViewHolder holder;
			if (view == null)
			{
				LayoutInflater inflater = LayoutInflater.from(CertChooser.this);
				view = inflater.inflate(R.layout.cert_item, parent, false);
				holder = new ViewHolder();
				holder.mAliasTextView = (TextView) view.findViewById(R.id.cert_item_alias);
				holder.mSubjectTextView = (TextView) view.findViewById(R.id.cert_item_subject);
				holder.mRadioButton = (RadioButton) view.findViewById(R.id.cert_item_selected);
				view.setTag(holder);
			}
			else
			{
				holder = (ViewHolder) view.getTag();
			}

			String alias = mAliases.get(adapterPosition);

			holder.mAliasTextView.setText(alias);

			String subject = mSubjects.get(adapterPosition);
			if (subject == null)
			{
				new CertLoader(adapterPosition, holder.mSubjectTextView).execute();
			}
			else
			{
				holder.mSubjectTextView.setText(subject);
			}

			ListView lv = (ListView) parent;
			int listViewCheckedItemPosition = lv.getCheckedItemPosition();
			int adapterCheckedItemPosition = listViewCheckedItemPosition - 1;
			holder.mRadioButton.setChecked(adapterPosition == adapterCheckedItemPosition);
			return view;
		}

		private class CertLoader extends AsyncTask<Void, Void, String>
		{
			private final int		mAdapterPosition;

			private final TextView	mSubjectView;

			private CertLoader(int adapterPosition, TextView subjectView)
			{
				mAdapterPosition = adapterPosition;
				mSubjectView = subjectView;
			}

			@Override
			protected String doInBackground(Void... params)
			{
				String alias = mAliases.get(mAdapterPosition);
				byte[] buf = mKeyStore.get(Credentials.USER_CERTIFICATE + alias);
				if (buf == null)
				{
					return null;
				}
				X509Certificate[] chains;
				try
				{
					chains = (X509Certificate[])new ObjectInputStream(new ByteArrayInputStream(buf)).readObject();
					// bouncycastle can handle the emailAddress OID of 1.2.840.113549.1.9.1
					// X500Principal subjectPrincipal = cert.getSubjectX500Principal();
					// X509Name subjectName = X509Name.getInstance(subjectPrincipal.getEncoded());
					// String subjectString = subjectName.toString(true, X509Name.DefaultSymbols);
					return  chains[0].getSubjectX500Principal().getName();
				}
				catch (Exception e)
				{
					return null;
				}
			}

			@Override
			protected void onPostExecute(String subjectString)
			{
				mSubjects.set(mAdapterPosition, subjectString);
				mSubjectView.setText(subjectString);
			}
		}
	}

	@Override
	protected void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);
	}

	@Override
	protected void onResume()
	{
		super.onResume();
		showCertChooserDialog();
	}

	private void displayCertChooserDialog(final CertificateAdapter adapter)
	{
		AlertDialog.Builder builder = new AlertDialog.Builder(this);

		TextView contextView = (TextView) View.inflate(this, R.layout.cert_chooser_header, null);

		final ListView lv = (ListView) View.inflate(this, R.layout.cert_chooser, null);
		lv.addHeaderView(contextView, null, false);
		lv.setAdapter(adapter);
		builder.setView(lv);

		lv.setOnItemClickListener(new AdapterView.OnItemClickListener()
		{

			@Override
			public void onItemClick(AdapterView<?> parent, View view, int position, long id)
			{
				lv.setItemChecked(position, true);
			}
		});

		boolean empty = adapter.mAliases.isEmpty();
		int negativeLabel = empty ? android.R.string.cancel : R.string.deny_button;
		builder.setNegativeButton(negativeLabel, new DialogInterface.OnClickListener()
		{
			@Override
			public void onClick(DialogInterface dialog, int id)
			{
				dialog.cancel(); // will cause OnDismissListener to be called
			}
		});

		String title;
		Resources res = getResources();
		if (empty)
		{
			title = res.getString(R.string.title_no_certs);
		}
		else
		{
			title = res.getString(R.string.title_select_cert);
			String alias = getIntent().getStringExtra(CertInstaller.EXTRA_ALIAS);
			if (alias != null)
			{
				// if alias was requested, set it if found
				int adapterPosition = adapter.mAliases.indexOf(alias);
				if (adapterPosition != -1)
				{
					int listViewPosition = adapterPosition + 1;
					lv.setItemChecked(listViewPosition, true);
				}
			}
			else if (adapter.mAliases.size() == 1)
			{
				// if only one choice, preselect it
				int adapterPosition = 0;
				int listViewPosition = adapterPosition + 1;
				lv.setItemChecked(listViewPosition, true);
			}

			builder.setPositiveButton(R.string.allow_button, new DialogInterface.OnClickListener()
			{
				@Override
				public void onClick(DialogInterface dialog, int id)
				{
					int listViewPosition = lv.getCheckedItemPosition();
					int adapterPosition = listViewPosition - 1;
					String alias = ((adapterPosition >= 0) ? adapter.getItem(adapterPosition)
							: null);
					finish(alias);
				}
			});
		}
		builder.setTitle(title);
		final Dialog dialog = builder.create();

		String pkg = getPackageName();
		PackageManager pm = getPackageManager();
		CharSequence applicationLabel;
		try
		{
			applicationLabel = pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString();
		}
		catch (PackageManager.NameNotFoundException e)
		{
			applicationLabel = pkg;
		}
		String appMessage = String.format(res.getString(R.string.requesting_application),
				applicationLabel);

		String contextMessage = appMessage;
		String host = getIntent().getStringExtra(CertInstaller.EXTRA_HOST);
		if (host != null)
		{
			String hostString = host;
			int port = getIntent().getIntExtra(CertInstaller.EXTRA_PORT, -1);
			if (port != -1)
			{
				hostString += ":" + port;
			}
			String hostMessage = String.format(res.getString(R.string.requesting_server),
					hostString);
			if (contextMessage == null)
			{
				contextMessage = hostMessage;
			}
			else
			{
				contextMessage += " " + hostMessage;
			}
		}
		contextView.setText(contextMessage);

		dialog.setOnCancelListener(new DialogInterface.OnCancelListener()
		{
			@Override
			public void onCancel(DialogInterface dialog)
			{
				finish(null);
			}
		});
		dialog.show();
	}

	private void finish(String alias)
	{
		int idCallBack = getIntent().getIntExtra(EXTRA_RESPONSE, -1);
		KeyChainCallBack callBack = sCallBacks.get(idCallBack);
		sCallBacks.remove(idCallBack);
		if (callBack != null)
			callBack.alias(alias);
		finish();
	}

	public static void addResponse(Intent intent, final KeyChainCallBack response)
	{
		int id = sCallBackId++;
		sCallBacks.append(id, response);
		intent.putExtra(EXTRA_RESPONSE, id);
	}
}
