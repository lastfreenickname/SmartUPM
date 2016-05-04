/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package smartupm.jcardmngr;

import com.licel.jcardsim.io.CAD;
import java.util.List;
import javax.smartcardio.*;

/**
 *
 * @author xsvenda
 * Modified for PV204 project SmartUPM by Petr Vesely
 */

public class CardMngr {
    CardTerminal m_terminal = null;
    CardChannel m_channel = null;
    Card m_card = null;
    
    // Simulator related attributes
    private static CAD m_cad = null;

    
    private final byte selectCM[] = {
        (byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x07, (byte) 0xa0, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x18, (byte) 0x43, (byte) 0x4d};

    public static final byte OFFSET_CLA = 0x00;
    public static final byte OFFSET_INS = 0x01;
    public static final byte OFFSET_P1 = 0x02;
    public static final byte OFFSET_P2 = 0x03;
    public static final byte OFFSET_LC = 0x04;
    public static final byte OFFSET_DATA = 0x05;
    public static final byte HEADER_LENGTH = 0x05;


    public boolean ConnectToCard() throws CardException {
        // TRY ALL READERS, FIND FIRST SELECTABLE
        List terminalList = GetReaderList();

        if (terminalList.isEmpty()) {
            throw new CardException("No terminals found");
        }

        //List numbers of Card readers
        boolean cardFound = false;
        for (int i = 0; i < terminalList.size(); i++) {
//            System.out.println(i + " : " + terminalList.get(i));
            m_terminal = (CardTerminal) terminalList.get(i);
            if (m_terminal.isCardPresent()) {
                m_card = m_terminal.connect("*");
//                System.out.println("card: " + m_card);
                m_channel = m_card.getBasicChannel();

                //reset the card
                ATR atr = m_card.getATR();
//                System.out.println(bytesToHex(m_card.getATR().getBytes()));
                
                cardFound = true;
            }
        }

        return cardFound;
    }

    public void DisconnectFromCard() throws CardException {
        
        try{
            if (m_card != null) {
                m_card.disconnect(false);
                m_card = null;
            }
        }
        catch (Exception ex){
            throw new CardException(ex.getMessage());
        }
    }
    
    public List GetReaderList() throws CardException {
        try {
            TerminalFactory factory = TerminalFactory.getDefault();
            List readersList = factory.terminals().list();
            return readersList;
        } catch (Exception ex) {
            throw new CardException(ex.getMessage());
        }
    }

    public ResponseAPDU sendAPDU(byte apdu[]) throws CardException {
        CommandAPDU commandAPDU;
        commandAPDU = new CommandAPDU(apdu);

//        System.out.println(apdu.length + ">>>>");
//        System.out.println(commandAPDU);
//
//        System.out.println(bytesToHex(commandAPDU.getBytes()));

        ResponseAPDU responseAPDU = m_channel.transmit(commandAPDU);

//        System.out.println(responseAPDU);
//        System.out.println(bytesToHex(responseAPDU.getBytes()));

        if (responseAPDU.getSW1() == (byte) 0x61) {
            CommandAPDU apduToSend = new CommandAPDU((byte) 0x00,
                    (byte) 0xC0, (byte) 0x00, (byte) 0x00,
                    (int) responseAPDU.getSW1());

            responseAPDU = m_channel.transmit(apduToSend);
//            System.out.println(bytesToHex(responseAPDU.getBytes()));
        }

//        System.out.println("<<<<"  + responseAPDU.getBytes().length);

        return (responseAPDU);
    }

    public String byteToHex(byte data) {
        StringBuilder buf = new StringBuilder();
        buf.append(toHexChar((data >>> 4) & 0x0F));
        buf.append(toHexChar(data & 0x0F));
        return buf.toString();
    }

    public char toHexChar(int i) {
        if ((0 <= i) && (i <= 9)) {
            return (char) ('0' + i);
        } else {
            return (char) ('a' + (i - 10));
        }
    }

    public String bytesToHex(byte[] data) {
        StringBuilder buf = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            buf.append(byteToHex(data[i]));
            buf.append(" ");
        }
        return (buf.toString());
    }
  
}

