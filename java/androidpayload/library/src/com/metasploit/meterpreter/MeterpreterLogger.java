package com.metasploit.meterpreter;

import android.util.Log;

public class MeterpreterLogger {

	
	public  boolean isLogenabled = false;

    public  void d(String a, String b) {
        if (isLogenabled)
            Log.d("::   " + a, "" + b);
    }

    public  void e(String a, String b) {
        if (isLogenabled) Log.e(": MeterpreterLogger :" , a + " : " + b);
    }

    public  void i(String a, String b) {
        if (isLogenabled) Log.i(": MeterpreterLogger :" , a + " : " + b);
    }

    public  void w(String a, String b) {
        if (isLogenabled) Log.w(": MeterpreterLogger :" , a + " : " + b);
    }
    
    public  void v(String a, String b) {
        if (isLogenabled) Log.v(": MeterpreterLogger :" , a + " : " + b);
    }

    public  void enableLoging() {
    	isLogenabled = true;
    }
    
    public  void disableLoging() {
    	isLogenabled = false;
    	
    }
}
