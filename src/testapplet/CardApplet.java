package testapplet;

// specific import for Javacard API access
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class CardApplet extends javacard.framework.Applet
{
    // MAIN INSTRUCTION CLASS
    final static byte CLA_HEADER                = (byte) 0xB0;

    //testing git
    
    // INSTRUCTIONS
    final static byte INS_SETKEY                    = (byte) 0x52;
    final static byte INS_GETKEY                    = (byte) 0x53;
    final static short SW_BAD_PIN                    = (short) 0x6900;

    private   byte[][]        KeyArray = new byte[4][32];
    private   byte[][]        IVArray = new byte[4][16];
    private   byte[][]        PINArray = new byte[4][4];
    private   byte           NumKey = 0;
    private   byte           DBID = 0;
    private   RandomData     m_secureRandom = null;
 
    protected CardApplet(byte[] buffer, short offset, byte length)
    {   
         m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        register();
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
      byte[]    RandomNumber = new byte[32+16];
      m_secureRandom.generateData(RandomNumber, (byte)0, (byte) (32+16));
      for(short i=0; i<32; i++)
        KeyArray[NumKey][i] = RandomNumber[i];
      for(short i=0; i<16; i++)
        IVArray[NumKey][i] = RandomNumber[i+32];
      for(short i=0; i<4; i++)
        PINArray[NumKey][i] = apdubuf[i+ISO7816.OFFSET_CDATA];
      NumKey++;
      //Send DBID
      apdubuf[ISO7816.OFFSET_CDATA] = (byte)(NumKey-1);
      apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (byte)1);
    }

    // VERIFY PIN
     void GetKey(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();
      byte match=1;
      for(short j=0; j<NumKey; j++)
      {
          match = 1;
          for(short i=0; i<4; i++)
          {
              if(PINArray[j][i]!=apdubuf[i+ISO7816.OFFSET_CDATA+1])
              {
                  match=0;
                  break;
              }
          }
          if(match==1) 
          {
              DBID = (byte)j;
              apdubuf[ISO7816.OFFSET_CDATA] = (byte)DBID;
              for(short i=0; i<32; i++)
                apdubuf[i+ISO7816.OFFSET_CDATA+1] = KeyArray[DBID][i];
              for(short i=0; i<16; i++)
                apdubuf[i+ISO7816.OFFSET_CDATA+33] = IVArray[DBID][i];              
              apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (byte)(1+32+16));
              return;
          }
      }
       ISOException.throwIt(SW_BAD_PIN);
      
    }

}
