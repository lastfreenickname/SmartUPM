/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package smartupm.jcardmngr;
//TODO import correct applet simulation
import com._17od.upm.crypto.InvalidPasswordException;
import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;
import testapplet.CardApplet;

/**
 *
 * @author petr.vesely
 */
public class AppletInterface {



    static CardMngr cardManager = new CardMngr();
    // TODO fix applet AID to final
    private static final byte APPLET_AID[] = {
        (byte) 0x53, (byte) 0x6D, (byte) 0x61, (byte) 0x72, (byte) 0x74, 
        (byte) 0x55, (byte) 0x50, (byte) 0x4D, (byte) 0x61, (byte) 0x70, 
        (byte) 0x70, (byte) 0x6C};
    // TODO fix applet AID to final
    private static final byte SELECT_APPLET[] = {(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0C,
        (byte) 0x53, (byte) 0x6D, (byte) 0x61, (byte) 0x72, (byte) 0x74, (byte) 0x55, (byte) 0x50, (byte) 0x4D, (byte) 0x61, 
        (byte) 0x70, (byte) 0x70, (byte) 0x6C};

    // INSTRUCTIONS
    // TODO insert correct instructions
    public final static byte SEND_INS_GETKEY[]                = {(byte) 0xB0, (byte) 0x53};
    public final static byte SEND_INS_SETKEY[]                = {(byte) 0xB0, (byte) 0x52};
//    public final static byte SEND_INS_RANDOM[]                = {(byte) 0xB0, (byte) 0x54};
//    public final static byte SEND_INS_RETURN[]                = {(byte) 0xB0, (byte) 0x57};
    public final static byte EMPTY[]                          = {};

    // STATUS WORDS
    // TODO insert correct status words
    final static short OK                               = (short) 0x9000;
    final static short SW_BAD_PIN                       = (short) 0x6900;
    final static short SW_FILE_NOT_FOUND                = (short) 0x6A82;
    
    public AppletInterface() throws CardException, SmartUPMAppletException, InvalidPasswordException {

        // Init real card
        ResponseAPDU responseAPDU;
        if (cardManager.ConnectToCard()) {
            // Select our application on card
            responseAPDU = cardManager.sendAPDU(SELECT_APPLET);
            parseStatusWord(responseAPDU.getBytes(), responseAPDU.getBytes().length);
        }
        else {
            throw new CardException("Unable to connect to card. Is reader connected and card inserted?");
        }
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
//        try {

            ResponseAPDU responseAPDU = cardManager.sendAPDU(apdu);
          
            return responseAPDU;
//
//        } catch (Exception ex) {
//            System.out.println("Exception : " + ex);
//        }
//        return null;
    }
    
    private boolean parseStatusWord(byte[] status, int arraylength) throws SmartUPMAppletException, InvalidPasswordException{
        if(arraylength!=2) throw new SmartUPMAppletException("Unexpected response from card or applet.");
        short shortstatus= (short) ((short)0x100 * (short)(status[0]& 0xff) + (short)(status[1]& 0xff));
        switch (shortstatus) {
            case OK:
                return true;
            case SW_BAD_PIN:
                throw new InvalidPasswordException();
            case SW_FILE_NOT_FOUND:
                throw new SmartUPMAppletException("SmartUPM applet not found on card.");
            default:
                throw new SmartUPMAppletException("Unexpected response from card or applet.");
        }
    }

    public byte[] sendAppletInstruction(byte[] instruction, byte P1, byte P2, byte[] additionalData) throws SmartUPMAppletException, InvalidPasswordException, CardException{

//        try{
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

            if (parseStatusWord(status, status.length)) return result;
            else return null;
//        }
//        catch(Exception ex){
//            throw ex;
//        }
    }
    
}
