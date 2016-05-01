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
package com._17od.upm.database;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;

import com._17od.upm.crypto.CryptoException;
import com._17od.upm.crypto.EncryptionService;
import com._17od.upm.crypto.InvalidPasswordException;
import javax.smartcardio.CardException;
import smartupm.jcardmngr.SmartUPMAppletException;

/**
 * This factory is used to load or create a PasswordDatabase. Different versions
 * of the database need to be loaded slightly differently so this class takes
 * care of those differences.
 * 
 * Database versions and formats. The items between [] brackets are encrypted.
 *   3     >> MAGIC_NUMBER DB_VERSION SALT [DB_REVISION DB_OPTIONS ACCOUNTS]
 *      (all strings are encoded using UTF-8)
 *   2     >> MAGIC_NUMBER DB_VERSION SALT [DB_REVISION DB_OPTIONS ACCOUNTS]
 *   1.1.0 >> SALT [DB_HEADER DB_REVISION DB_OPTIONS ACCOUNTS]
 *   1.0.0 >> SALT [DB_HEADER ACCOUNTS]
 * 
 *   DB_VERSION = The structural version of the database
 *   SALT = The salt used to mix with the user password to create the key
 *   DB_HEADER = Was used to store the structural version of the database (pre version 2)
 *   DB_OPTIONS = Options relating to the database
 *   ACCOUNTS = The account information
 */
public class PasswordDatabasePersistence {

    private static final String FILE_HEADER = "SmartUPM";
    private static final int DB_VERSION = 3;

    private EncryptionService encryptionService;

    /**
     * Used when we have a databasePin and we want to get an instance of the class
     * so that we can call load(File, char[])  
     */
    public PasswordDatabasePersistence() {
    }

    /**
     * Used when we want to create a new database with the given databasePin
     * @param databasePin
     * @throws CryptoException
     * @throws com._17od.upm.crypto.InvalidPasswordException
     */
    public PasswordDatabasePersistence(char[] databasePin) throws CryptoException, InvalidPasswordException, SmartUPMAppletException, CardException {
        encryptionService = new EncryptionService(databasePin);
    }

    public PasswordDatabase load(File databaseFile) throws InvalidPasswordException, ProblemReadingDatabaseFile, IOException {

        byte[] fullDatabase = readFile(databaseFile);

        // Check the database is a minimum length
        if (fullDatabase.length < FILE_HEADER.getBytes().length+EncryptionService.DBID_LENGTH) {
            throw new ProblemReadingDatabaseFile("This file doesn't appear to be a SmartUPM password database");
        }

        PasswordDatabase passwordDatabase = null;
        ByteArrayInputStream is = null;
        Revision revision = null;
        DatabaseOptions dbOptions = null;
        HashMap accounts = null;
        Charset charset = Charset.forName("UTF-8");

        // Ensure this is a real UPM database by checking for the existence of 
        // the string "SmartUPM" at the start of the file
        byte[] header = new byte[FILE_HEADER.getBytes().length];
        System.arraycopy(fullDatabase, 0, header, 0, header.length);
        if (Arrays.equals(header, FILE_HEADER.getBytes())) {

            // Calculate the positions of each item in the file
            int dbVersionPos      = header.length;
            int dbidPos           = dbVersionPos + 1;
            int encryptedBytesPos = dbidPos + EncryptionService.DBID_LENGTH;

            // Get the database version 
            byte dbVersion = fullDatabase[dbVersionPos];

            if (dbVersion == 3) {
                byte[] dbid = new byte[EncryptionService.DBID_LENGTH];
                System.arraycopy(fullDatabase, dbidPos, dbid, 0, EncryptionService.DBID_LENGTH);
                int encryptedBytesLength = fullDatabase.length - encryptedBytesPos;
                byte[] encryptedBytes = new byte[encryptedBytesLength]; 
                System.arraycopy(fullDatabase, encryptedBytesPos, encryptedBytes, 0, encryptedBytesLength);

                //Attempt to decrypt the database information
                byte[] decryptedBytes;
                try {
                    decryptedBytes = encryptionService.decrypt(encryptedBytes);
                } catch (CryptoException e1) {
                    throw new InvalidPasswordException();
                }

                //If we've got here then the database was successfully decrypted 
                is = new ByteArrayInputStream(decryptedBytes);
                try {
                    revision = new Revision(is);
                    dbOptions = new DatabaseOptions(is);
    
                    // Read the remainder of the database in now
                    accounts = new HashMap();
                    try {
                        while (true) { //keep loading accounts until an EOFException is thrown
                            AccountInformation ai = new AccountInformation(is, charset);
                            accounts.put(ai.getAccountName(), ai);
                        }
                    } catch (EOFException e) {
                        //just means we hit eof
                    }
                    is.close();
                } catch (IOException e) {
                    throw new ProblemReadingDatabaseFile(e.getMessage(), e);
                }

                passwordDatabase = new PasswordDatabase(revision, dbOptions, accounts, databaseFile);
                 return passwordDatabase; 
            } else {
                 throw new ProblemReadingDatabaseFile("Don't know how to handle database version [" + dbVersion + "]");    
            }
        } else {
            throw new ProblemReadingDatabaseFile("This file doesn't appear to be a SmartUPM password database");
        }
     }

    public PasswordDatabase load(File databaseFile, char[] dbPin) throws IOException, ProblemReadingDatabaseFile, InvalidPasswordException, CryptoException, SmartUPMAppletException, CardException {

        byte[] fullDatabase;
        fullDatabase = readFile(databaseFile);

        // Check the database is a minimum length
        if (fullDatabase.length < FILE_HEADER.getBytes().length+EncryptionService.DBID_LENGTH) {
            throw new ProblemReadingDatabaseFile("This file doesn't appear to be a SmartUPM password database");
        }

        ByteArrayInputStream is = null;
        Revision revision = null;
        DatabaseOptions dbOptions = null;
        Charset charset = Charset.forName("UTF-8");

        // Ensure this is a real SmartUPM database by checking for the existence of 
        // the string "SmartUPM" at the start of the file
        byte[] header = new byte[FILE_HEADER.getBytes().length];
        System.arraycopy(fullDatabase, 0, header, 0, header.length);
        if (Arrays.equals(header, FILE_HEADER.getBytes())) {

            // Calculate the positions of each item in the file
            int dbVersionPos      = header.length;
            int dbidPos           = dbVersionPos + 1;
            int encryptedBytesPos = dbidPos + EncryptionService.DBID_LENGTH;

            // Get the database version 
            byte dbVersion = fullDatabase[dbVersionPos];

            if (dbVersion == 3) {
                byte[] dbid = new byte[EncryptionService.DBID_LENGTH];
                System.arraycopy(fullDatabase, dbidPos, dbid, 0, EncryptionService.DBID_LENGTH);
                int encryptedBytesLength = fullDatabase.length - encryptedBytesPos;
                byte[] encryptedBytes = new byte[encryptedBytesLength]; 
                System.arraycopy(fullDatabase, encryptedBytesPos, encryptedBytes, 0, encryptedBytesLength);

                //Attempt to decrypt the database information
                byte[] decryptedBytes;
                try {
                    encryptionService = new EncryptionService(dbPin, dbid);
                    decryptedBytes = encryptionService.decrypt(encryptedBytes);
                } catch (CryptoException e) {
                    throw new InvalidPasswordException();
                }

                //If we've got here then the database was successfully decrypted 
                is = new ByteArrayInputStream(decryptedBytes);
                revision = new Revision(is);
                dbOptions = new DatabaseOptions(is);
            } else {
                throw new ProblemReadingDatabaseFile("Don't know how to handle database version [" + dbVersion + "]");
            }
        
        // Read the remainder of the database in now
            HashMap accounts = new HashMap();
            try {
                while (true) { //keep loading accounts until an EOFException is thrown
                    AccountInformation ai = new AccountInformation(is, charset);
                    accounts.put(ai.getAccountName(), ai);
                }
            } catch (EOFException e) {
                //just means we hit eof
            }
            is.close();

            PasswordDatabase passwordDatabase = new PasswordDatabase(revision, dbOptions, accounts, databaseFile);
            return passwordDatabase;
 
        } else{
            throw new ProblemReadingDatabaseFile("This file doesn't appear to be a SmartUPM password database");
        }
    }

    public void save(PasswordDatabase database) throws IOException, CryptoException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        
        // Flatpack the database revision and options
        database.getRevisionObj().increment();
        database.getRevisionObj().flatPack(os);
        database.getDbOptions().flatPack(os);

        // Flatpack the accounts
        Iterator it = database.getAccountsHash().values().iterator();
        while (it.hasNext()) {
            AccountInformation ai = (AccountInformation) it.next();
            ai.flatPack(os);
        }
        os.close();
        byte[] dataToEncrypt = os.toByteArray();

        //Now encrypt the database data
        byte[] encryptedData = encryptionService.encrypt(dataToEncrypt);
        
        //Write the salt and the encrypted data out to the database file
        FileOutputStream fos = new FileOutputStream(database.getDatabaseFile());
        fos.write(FILE_HEADER.getBytes());
        fos.write(DB_VERSION);
        fos.write(encryptionService.getDbid());
        fos.write(encryptedData);
        fos.close();
    }

    public EncryptionService getEncryptionService() {
        return encryptionService;
    }

    private byte[] readFile(File file) throws IOException {
        InputStream is;
        try {
            is = new FileInputStream(file);
        } catch (IOException e) {
            throw new IOException("There was a problem with opening the file", e);
        }
    
        // Create the byte array to hold the data
        byte[] bytes = new byte[(int) file.length()];
    
        // Read in the bytes
        int offset = 0;
        int numRead = 0;
        
        try {
            while (offset < bytes.length
                    && (numRead=is.read(bytes, offset, bytes.length-offset)) >= 0) {
                offset += numRead;
            }
    
            // Ensure all the bytes have been read in
            if (offset < bytes.length) {
                throw new IOException("Could not completely read file " + file.getName());
            }
        } finally {
            is.close();
        }

        return bytes;
    }

}
