package com.example.test;

import android.os.Bundle;
import android.app.Activity;
import android.widget.TextView;
import android.widget.LinearLayout;
import android.util.AttributeSet;
import android.content.Context;
import android.view.Gravity;
import android.view.Window;

public class MainActivity extends Activity {
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		requestWindowFeature(Window.FEATURE_NO_TITLE);

		LinearLayout activity_main = new LinearLayout(this);
		activity_main.setLayoutParams(
				new LinearLayout.LayoutParams(
						LinearLayout.LayoutParams.MATCH_PARENT,
						LinearLayout.LayoutParams.MATCH_PARENT
					)
		);
		activity_main.setGravity(Gravity.CENTER);

		TextView hello_tv = new TextView(this);
		hello_tv.setText(getHelloString());

		activity_main.addView(hello_tv);

		setContentView(activity_main);
	}

	private native String getHelloString();

	static {
		System.loadLibrary("jni-example");
	}
}
