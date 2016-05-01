/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package smartupm.jcardmngr;
//TODO import correct applet simulation
import com._17od.upm.crypto.InvalidPasswordException;
import testapplet.CardApplet;

/**
 *
 * @author petr.vesely
 */
public class AppletInterface {



    static CardMngr cardManager = new CardMngr();
    // TODO fix applet AID to final
    private static byte APPLET_AID[] = {
        (byte) 0x4C, (byte) 0x61, (byte) 0x62, (byte) 0x61, (byte) 0x6B, (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};
    // TODO fix applet AID to final
//    private static byte SELECT_APPLET[] = {(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0b,
//        (byte) 0x4C, (byte) 0x61, (byte) 0x62, (byte) 0x61, (byte) 0x6B, (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};

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
    
    public AppletInterface() {
        // Init card simulator
        // byte[] installData = new byte[10]; // no special install data passed now - can be used to pass initial PIN, PUK etc.
        cardManager.prepareLocalSimulatorApplet(APPLET_AID, EMPTY, CardApplet.class);
    
        // Init real card
        // TODO real card
        
    }
    
    
    //Method used to construct APDU with instruction and optional additional data, send it and receive response
    public byte[] sendApduAndReceive(byte[] instruction, byte P1, byte P2, byte[] additionalData)  {

        short additionalDataLen = (short) additionalData.length;
        byte apdu[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];

        System.arraycopy(instruction, 0, apdu, 0, 2);
        apdu[CardMngr.OFFSET_P1]=P1;
        apdu[CardMngr.OFFSET_P2]=P2;
        apdu[CardMngr.OFFSET_LC]=(byte) additionalDataLen;
        if(additionalDataLen>0)
            System.arraycopy(additionalData,0,apdu, CardMngr.OFFSET_DATA,additionalDataLen);
        try {
            // TODO real card
            // TODO parse correct answers and error
            byte[] response = cardManager.sendAPDUSimulator(apdu);
          
            return response;

        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
        return null;
    }
    
    private boolean parseStatusWord(byte[] status, int arraylength) throws SmartUPMAppletException, InvalidPasswordException{
        if(arraylength!=2) return false;
        
//        short[] shortstatus=new short[2];
//        for (int i=0;i<2;i++) shortstatus[i]=(short)(status[i]& 0xff);
//        System.out.println(0x100 * shortstatus[0] + shortstatus[1]);
//      switch((short)(0x100 * shortstatus[0] + shortstatus[1])){
////        switch((short)i){
//            case OK: return true; break;
//            case SW_BAD_PIN: throw new SmartUPMAppletException ("PIN was not accepted."); break;
//            default: throw new SmartUPMAppletException ("Unexpected response from applet."); break;
//        }
        
        short shortstatus= (short) ((short)0x100 * (short)(status[0]& 0xff) + (short)(status[1]& 0xff));
        if(shortstatus==OK){
            return true;
        }
        else if (shortstatus==SW_BAD_PIN){
            throw new InvalidPasswordException();
        }
        else throw new SmartUPMAppletException ("Unexpected response from applet.");
    }

    public byte[] sendAppletInstruction(byte[] instruction, byte P1, byte P2, byte[] additionalData) throws SmartUPMAppletException, InvalidPasswordException{

        try{
            byte[] result=null;
            byte[] response=sendApduAndReceive(instruction, P1, P2, additionalData);

            if(response.length<2) throw new SmartUPMAppletException("Unexpected Applet Response.");

            //Applet response is at least 2 bytes, last 2 bytes are status word.

            if(response.length>2){
                result=new byte[response.length-2];
                System.arraycopy(response,0,result,0,result.length);
            }
            byte status[]=new byte[2];
            System.arraycopy(response,response.length-2,status,0,2); 

            if (parseStatusWord(status, status.length)) return result;
            else return null;
        }
        catch(Exception ex){
            throw ex;
        }
    }
    
}
