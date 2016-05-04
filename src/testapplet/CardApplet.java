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
    private   OwnerPIN[]       PINArray = new OwnerPIN[DB_CNT];
    
    private   byte           NumKey = 0;
    private   byte           DBID = 0;
    private   RandomData     m_secureRandom = null;
    
    private   byte          Temp [] = null;
    private   byte          RandomNumber[] = null;

    private   AESKey         m_aesKey = null;
    private   Cipher         m_encryptCipher = null;
    private   Cipher         m_decryptCipher = null;
    private   byte           m_ramArray[] = null;  // TEMPORARRY ARRAY IN RAM

   private static     byte[] key = {(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06,(byte) 0x07,(byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C, (byte) 0x0D, (byte) 0x0E,(byte) 0x0F};
     protected CardApplet(byte[] buffer, short offset, byte length)
    {   
         m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        register();
        for(short i=0; i<DB_CNT; i++) PINArray[i] = new OwnerPIN((byte) 3, PIN_LEN);
        for(short i=0; i<DB_CNT; i++) KeyArray[i] = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        for(short i=0; i<DB_CNT; i++) IVArray[i] = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        Temp = JCSystem.makeTransientByteArray(KEY_SIZE, JCSystem.CLEAR_ON_DESELECT);
        RandomNumber = JCSystem.makeTransientByteArray((byte)(KEY_SIZE+IV_SIZE), JCSystem.CLEAR_ON_DESELECT);
        
        m_aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        m_encryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
        m_decryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
        
        m_ramArray = new byte[16];
        m_ramArray = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
        m_aesKey.setKey(key, (short) 0);
        m_encryptCipher.init(m_aesKey, Cipher.MODE_ENCRYPT);
        //m_decryptCipher.init(m_aesKey, Cipher.MODE_DECRYPT);
        
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
      m_secureRandom.generateData(RandomNumber, (byte)0, (byte) (KEY_SIZE+IV_SIZE));
      KeyArray[NumKey].setKey(RandomNumber, (byte)0);  
      IVArray[NumKey].setKey(RandomNumber, KEY_SIZE);   
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
      DBID = apdubuf[ISO7816.OFFSET_CDATA];
      if (PINArray[DBID].check(apdubuf, (byte)(ISO7816.OFFSET_CDATA+1), (byte) (dataLen-1)) == true)
      {
        apdubuf[ISO7816.OFFSET_CDATA] = DBID;
        KeyArray[DBID].getKey(Temp, (byte)0);
        Util.arrayCopy(Temp, (byte)0, apdubuf, (byte)(ISO7816.OFFSET_CDATA+1), KEY_SIZE);
        IVArray[DBID].getKey(Temp, (byte)0);
        Util.arrayCopy(Temp, (byte)0, apdubuf, (byte)(ISO7816.OFFSET_CDATA+33), IV_SIZE);
        
        //Encrypt 
        m_encryptCipher.doFinal(apdubuf, (byte)(ISO7816.OFFSET_CDATA+1), (byte)16, m_ramArray, (short) 0);
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, (byte)(ISO7816.OFFSET_CDATA+1), (byte)16);
        m_encryptCipher.doFinal(apdubuf, (byte)(ISO7816.OFFSET_CDATA+17), (byte)16, m_ramArray, (short) 0);
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, (byte)(ISO7816.OFFSET_CDATA+17), (byte)16);
        m_encryptCipher.doFinal(apdubuf, (byte)(ISO7816.OFFSET_CDATA+33), (byte)16, m_ramArray, (short) 0);
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, (byte)(ISO7816.OFFSET_CDATA+33), (byte)16);
        
        
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (byte)(1+KEY_SIZE+IV_SIZE));
        return;
      }
       ISOException.throwIt(SW_BAD_PIN);
      
    }

}
