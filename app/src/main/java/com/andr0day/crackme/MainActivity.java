package com.andr0day.crackme;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

public class MainActivity extends AppCompatActivity {

    static {
        System.loadLibrary("crack");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        final EditText txt = (EditText) findViewById(R.id.txt);
        Button btn = (Button) findViewById(R.id.btn);

        assert btn != null;
        btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String content = txt.getText().toString();
                if (checkStr(content)) {
                    Toast.makeText(MainActivity.this, "right, congratulations!!!", Toast.LENGTH_LONG).show();
                } else {
                    Toast.makeText(MainActivity.this, "not right", Toast.LENGTH_LONG).show();
                }
            }
        });
    }

    private native boolean checkStr(String txt);
}
