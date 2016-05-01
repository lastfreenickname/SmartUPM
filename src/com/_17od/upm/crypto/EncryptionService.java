/*
 * Universal Password Manager
 * Copyright (C) 2005-2013 Adrian Smith
 *
 * This file is part of Universal Password Manager.
 *   
 * Universal Password Manager is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Universal Password Manager is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Universal Password Manager; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
package com._17od.upm.crypto;


import com._17od.upm.util.Util;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.*;
import smartupm.jcardmngr.*;


public class EncryptionService {

//    private static final String randomAlgorithm = "SHA1PRNG";
    public static final short DBID_LENGTH = 1;
    public static final short AESKEY_LENGTH = 32;
    public static final short IV_LENGTH = 16;
    private byte[] dbid;
    private byte[] appletKeyResponse;
    private BufferedBlockCipher encryptCipher;
    private BufferedBlockCipher decryptCipher;
    private static AppletInterface appIface;
    
    public EncryptionService(char[] databasePin) throws SmartUPMAppletException, InvalidPasswordException {
        this(databasePin,null);
    }

    public EncryptionService(char[] databasePin, byte[] dbid) throws SmartUPMAppletException, InvalidPasswordException {
        if (appIface==null) appIface=new AppletInterface();  //the check for null is needed because of card simulator, to have applet persistency
        this.dbid=dbid;
        initCipher(databasePin);
    }

    private void initCipher(char[] databasePin) throws SmartUPMAppletException, InvalidPasswordException {
        byte[] databasePinBytes=new String(databasePin).getBytes(Charset.forName("UTF-8"));
        try{
            if (dbid==null) {
                // call without dbid means we are setting up new DB and are sending PIN to applet. Applet will return new DBID or AppletInterface will throw exception.
                dbid=appIface.sendAppletInstruction(AppletInterface.SEND_INS_SETKEY,(byte)0, (byte) 0, databasePinBytes);
            }
            // here we ask applet for keys for given dbid and PIN. (if creating new DB, we just return the dbid we just received above.
            appletKeyResponse=appIface.sendAppletInstruction(AppletInterface.SEND_INS_GETKEY,(byte)0, (byte) 0, Util.mergeArrays(dbid,databasePinBytes));    
        }
        catch (SmartUPMAppletException | InvalidPasswordException ex){
            throw ex;
        }
        
        //if we get here without exception, we received AES key and IV from applet without exception (no IO problems, PIN was accepted etc.)
        //we initialize the cipher engine with received key and IV.
        KeyParameter aesKey=new KeyParameter(Util.cutArray(appletKeyResponse,DBID_LENGTH,AESKEY_LENGTH));
        ParametersWithIV keyParams = new ParametersWithIV(aesKey, Util.cutArray(appletKeyResponse, DBID_LENGTH+AESKEY_LENGTH, IV_LENGTH));
                       
                
        encryptCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new PKCS7Padding());
        encryptCipher.init(true, keyParams);
        decryptCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new PKCS7Padding());
        decryptCipher.init(false, keyParams);
    }


    public byte[] encrypt(byte[] plainText) throws CryptoException {
        byte[] encryptedBytes = new byte[encryptCipher.getOutputSize(plainText.length)];
        int outputLength = encryptCipher.processBytes(plainText, 0, plainText.length, encryptedBytes, 0);
        try {
            outputLength += encryptCipher.doFinal(encryptedBytes, outputLength);
        } catch (InvalidCipherTextException e) {
            throw new CryptoException(e);
        }

        byte[] results = new byte[outputLength];
        System.arraycopy(encryptedBytes, 0, results, 0, outputLength);
        return results;
    }
    
    public byte[] decrypt(byte[] encryptedBytes) throws CryptoException {
        byte[] decryptedBytes = new byte[decryptCipher.getOutputSize(encryptedBytes.length)];
        int outputLength = decryptCipher.processBytes(encryptedBytes, 0, encryptedBytes.length, decryptedBytes, 0);
        try {
            outputLength += decryptCipher.doFinal(decryptedBytes, outputLength);
        } catch (InvalidCipherTextException e) {
            throw new CryptoException(e);
        }

        byte[] results = new byte[outputLength];
        System.arraycopy(decryptedBytes, 0, results, 0, outputLength);
        return results;
    }

    public byte[] getDbid() {
        return dbid;
    }

}
