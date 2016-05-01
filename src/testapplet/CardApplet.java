package testapplet;

// specific import for Javacard API access
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class CardApplet extends javacard.framework.Applet
{
    final static byte PIN_LEN                       = (byte) 16;
    final static byte DB_CNT                        =  (byte) 4;
    final static byte IV_SIZE                       = (byte) 16;
    final static byte KEY_SIZE                      = (byte) 32;
    
    // MAIN INSTRUCTION CLASS
    final static byte CLA_HEADER                = (byte) 0xB0;

    // INSTRUCTIONS
    final static byte INS_SETKEY                    = (byte) 0x52;
    final static byte INS_GETKEY                    = (byte) 0x53;
    final static short SW_BAD_PIN                    = (short) 0x6900;

    private   AESKey[]         KeyArray = new AESKey[DB_CNT];
    private   AESKey[]         IVArray = new AESKey[DB_CNT];
    private   OwnerPIN[]        PINArray = new OwnerPIN[DB_CNT];
    
    private   byte           NumKey = 0;
    private   byte           DBID = 0;
    private   RandomData     m_secureRandom = null;
    
    protected CardApplet(byte[] buffer, short offset, byte length)
    {   
         m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        register();
        for(short i=0; i<DB_CNT; i++) PINArray[i] = new OwnerPIN((byte) 3, (byte) PIN_LEN);
        for(short i=0; i<DB_CNT; i++) KeyArray[i] = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        for(short i=0; i<DB_CNT; i++) IVArray[i] = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException
    {
        // applet  instance creation 
        new CardApplet (bArray, bOffset, bLength);
    }

    public void process(APDU apdu) throws ISOException
    {
        byte[] apduBuffer = apdu.getBuffer();
        
        if (selectingApplet())
            return;

        // APDU instruction parser
        if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_HEADER) {
            switch ( apduBuffer[ISO7816.OFFSET_INS] )
            {
                case INS_SETKEY: SetKey(apdu); break;
                case INS_GETKEY: GetKey(apdu); break;
                default :
                    // The INS code is not supported by the dispatcher
                    ISOException.throwIt( ISO7816.SW_INS_NOT_SUPPORTED ) ;
                break ;

            }
        }
        else ISOException.throwIt( ISO7816.SW_CLA_NOT_SUPPORTED);
    }

    void SetKey(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();
      byte[]    RandomNumber = new byte[KEY_SIZE+IV_SIZE];
      m_secureRandom.generateData(RandomNumber, (byte)0, (byte) (KEY_SIZE+IV_SIZE));
      KeyArray[NumKey].setKey(RandomNumber, (byte)0);  
      IVArray[NumKey].setKey(RandomNumber, (byte)KEY_SIZE);   
      PINArray[NumKey].update(apdubuf,ISO7816.OFFSET_CDATA, (byte)dataLen);
      NumKey++;
      //Send DBID
      apdubuf[ISO7816.OFFSET_CDATA] = (byte)(NumKey-1);
      apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (byte)1);
    }

    // VERIFY PIN
     void GetKey(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();
      byte[]    Temp = new byte[32];
      byte match=1;
      DBID = apdubuf[ISO7816.OFFSET_CDATA];
      if (PINArray[DBID].check(apdubuf, (byte)(ISO7816.OFFSET_CDATA+1), (byte) (dataLen-1)) == true)
      {
        apdubuf[ISO7816.OFFSET_CDATA] = (byte)DBID;
        KeyArray[DBID].getKey(Temp, (byte)0);
        for(short i=0; i<KEY_SIZE; i++)
          apdubuf[i+ISO7816.OFFSET_CDATA+1] = Temp[i];
        IVArray[DBID].getKey(Temp, (byte)0);
        for(short i=0; i<IV_SIZE; i++)
          apdubuf[i+ISO7816.OFFSET_CDATA+33] = Temp[i];              
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (byte)(1+KEY_SIZE+IV_SIZE));
        return;
      }
       ISOException.throwIt(SW_BAD_PIN);
      
    }

}
