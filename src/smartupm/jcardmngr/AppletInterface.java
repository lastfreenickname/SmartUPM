/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package smartupm.jcardmngr;
import com._17od.upm.crypto.InvalidPasswordException;
import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.*;


/**
 *
 * @author petr.vesely
 */
public class AppletInterface {



    static CardMngr cardManager = new CardMngr();
    private static final byte APPLET_AID[] = {
        (byte) 0x53, (byte) 0x6D, (byte) 0x61, (byte) 0x72, (byte) 0x74, 
        (byte) 0x55, (byte) 0x50, (byte) 0x4D, (byte) 0x61, (byte) 0x70, 
        (byte) 0x70, (byte) 0x6C};
    private static final byte SELECT_APPLET[] = {(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0C,
        (byte) 0x53, (byte) 0x6D, (byte) 0x61, (byte) 0x72, (byte) 0x74, (byte) 0x55, (byte) 0x50, (byte) 0x4D, (byte) 0x61, 
        (byte) 0x70, (byte) 0x70, (byte) 0x6C};

    // INSTRUCTIONS
    public final static byte SEND_INS_GETKEY[]                = {(byte) 0xB0, (byte) 0x53};
    public final static byte SEND_INS_SETKEY[]                = {(byte) 0xB0, (byte) 0x52};

    public final static byte EMPTY[]                          = {};

    // STATUS WORDS
    final static short OK                               = (short) 0x9000;
    final static short SW_BAD_PIN                       = (short) 0x6900;
    final static short SW_BAD_PIN_LASTATTEMPT           = (short) 0x6901;
    final static short SW_FILE_NOT_FOUND                = (short) 0x6A82;
    final static short SW_DB_PERMANENTLY_LOCKED         = (short) 0x7000;
    final static short SW_DB_COUNT_EXCEEDED             = (short) 0x7001;
    
    private AESEngine secure;
    
    public AppletInterface() throws CardException, SmartUPMAppletException, InvalidPasswordException {

        // Init real card
        ResponseAPDU responseAPDU;
        try{
            if (cardManager.ConnectToCard()) {
                // Select our application on card
                responseAPDU = cardManager.sendAPDU(SELECT_APPLET);
                parseStatusWord(responseAPDU.getBytes(), responseAPDU.getBytes().length);
            }
            else {
                throw new CardException("Unable to connect to card. Is reader connected and card inserted?");
            }
        }
        catch(CardException ex){
            throw new CardException("Unable to connect to card. Is reader connected and card inserted?");
        }
        
        secure= new AESEngine();
        byte[] key=new byte[16];
        for(int i=0;i<16;i++) key[i]=(byte)i;
        secure.init(false, new KeyParameter(key));
        
    }
    
    
    //Method used to construct APDU with instruction and optional additional data, send it and receive response
    public ResponseAPDU sendApduAndReceive(byte[] instruction, byte P1, byte P2, byte[] additionalData) throws CardException  {

        short additionalDataLen = (short) additionalData.length;
        byte apdu[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];

        System.arraycopy(instruction, 0, apdu, 0, 2);
        apdu[CardMngr.OFFSET_P1]=P1;
        apdu[CardMngr.OFFSET_P2]=P2;
        apdu[CardMngr.OFFSET_LC]=(byte) additionalDataLen;
        if(additionalDataLen>0)
            System.arraycopy(additionalData,0,apdu, CardMngr.OFFSET_DATA,additionalDataLen);

            ResponseAPDU responseAPDU = cardManager.sendAPDU(apdu);
          
            return responseAPDU;

    }
    
    private boolean parseStatusWord(byte[] status, int arraylength) throws SmartUPMAppletException, InvalidPasswordException{
        if(arraylength!=2) throw new SmartUPMAppletException("Unexpected response from card or applet.");
        short shortstatus= (short) ((short)0x100 * (short)(status[0]& 0xff) + (short)(status[1]& 0xff));
        switch (shortstatus) {
            case OK:
                return true;
            case SW_BAD_PIN:
                throw new InvalidPasswordException();
            case SW_BAD_PIN_LASTATTEMPT:
                throw new InvalidPasswordException(" Last attempt before DB keys are erased!");
            case SW_FILE_NOT_FOUND:
                throw new SmartUPMAppletException("SmartUPM applet not found on card.");
            case SW_DB_PERMANENTLY_LOCKED:
                throw new SmartUPMAppletException("DB keys were permanently erased after three unsuccessful PIN attempts.");
            case SW_DB_COUNT_EXCEEDED:   
                throw new SmartUPMAppletException("This applet has no room for new database keys. Buy new card for only $99.99!");
                
            default:
                throw new SmartUPMAppletException("Unexpected response from card or applet.");
        }
    }

    public byte[] sendAppletInstruction(byte[] instruction, byte P1, byte P2, byte[] additionalData) throws SmartUPMAppletException, InvalidPasswordException, CardException{

            byte[] result=null;
            ResponseAPDU responseAPDU=sendApduAndReceive(instruction, P1, P2, additionalData);

            if(responseAPDU.getBytes().length<2) throw new SmartUPMAppletException("Unexpected response from applet.");

            //Applet response is at least 2 bytes, last 2 bytes are status word.

            if(responseAPDU.getBytes().length>2){
                result=new byte[responseAPDU.getBytes().length-2];
                System.arraycopy(responseAPDU.getBytes(),0,result,0,result.length);
            }
            byte status[]=new byte[2];
            System.arraycopy(responseAPDU.getBytes(),responseAPDU.getBytes().length-2,status,0,2); 

            if (parseStatusWord(status, status.length)){
                if(result.length==48){
                //card returned encryption keys
                    secure.processBlock(result, 0, result, 0);
                    secure.processBlock(result, 16, result, 16);
                    secure.processBlock(result, 32, result, 32);
                }
                return result;
            }
            else return null;
    }
}
