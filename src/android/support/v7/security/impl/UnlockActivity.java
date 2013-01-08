package android.support.v7.security.impl;

import android.app.Activity;

public class UnlockActivity extends Activity
{
	@Override
	protected void onResume()
	{
		super.onResume();
		finish();
	}
}
