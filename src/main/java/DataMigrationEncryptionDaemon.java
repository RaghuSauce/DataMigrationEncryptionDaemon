/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */


import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.kms.KmsMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
//import com.sun.xml.internal.bind.v2.TODO;
import org.apache.commons.io.FilenameUtils;

import static com.amazonaws.encryptionsdk.CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;

/**
 * <p>
 * Encrypts and then decrypts a string under a KMS key
 *
 * <p>
 * Arguments:
 * <ol>
 * <li>Key ARN: For help finding the Amazon Resource Name (ARN) of your KMS customer master 
 *    key (CMK), see 'Viewing Keys' at http://docs.aws.amazon.com/kms/latest/developerguide/viewing-keys.html
 * <li>String to encrypt
 * </ol>
 */
public class DataMigrationEncryptionDaemon {
    protected static CryptoAlgorithm CRYPTOALGO;
    private static  String inputFolder;
    private static  String outputFolder;
    private static String keyArn;

    public static void encryptionGarbage(){
        keyArn = "arn:aws:kms:us-east-1:681897778628:key/03c2b4db-a110-416b-ba49-66d41d834bb5";
        String data = "hello world";

        // Instantiate the SDK
        final AwsCrypto crypto = new AwsCrypto();

        // Set up the KmsMasterKeyProvider backed by the default credentials
        final KmsMasterKeyProvider prov = new KmsMasterKeyProvider(keyArn);

        // Encrypt the data
        //
        // Most encrypted data should have an associated encryption context
        // to protect integrity. This sample uses placeholder values.
        //
        // For more information see:
        // blogs.aws.amazon.com/security/post/Tx2LZ6WBJJANTNW/How-to-Protect-the-Integrity-of-Your-Encrypted-Data-by-Using-AWS-Key-Management
        final Map<String, String> context = Collections.singletonMap("Example", "String");

        final String ciphertext = crypto.encryptString(prov, data, context).getResult();
        System.out.println("Ciphertext: " + ciphertext);

        // Decrypt the data
        final CryptoResult<String, KmsMasterKey> decryptResult = crypto.decryptString(prov, ciphertext);

        // Before returning the plaintext, verify that the customer master key that
        // was used in the encryption operation was the one supplied to the master key provider.
        if (!decryptResult.getMasterKeyIds().get(0).equals(keyArn)) {
            throw new IllegalStateException("Wrong key ID!");
        }

        // Also, verify that the encryption context in the result contains the
        // encryption context supplied to the encryptString method. Because the
        // SDK can add values to the encryption context, don't require that
        // the entire context matches.
        for (final Map.Entry<String, String> e : context.entrySet()) {
            if (!e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey()))) {
                throw new IllegalStateException("Wrong Encryption Context!");
            }
        }

        // Now we can return the plaintext data
        System.out.println("Decrypted: " + decryptResult.getResult());
    }
    public static void main(final String[] args) throws IOException {
        if(args.length == 3) {
            String flag = args[0];
            String target = args[1];
            String destination = args[2];
            switch (flag) {
                //one file is passed to be encrypted
                case "ef" :{
                    DataMigrationEncryptionDaemon encryptionDaemon = new DataMigrationEncryptionDaemon(target,destination);
                    encryptionDaemon.encryptFile();
                    break;
                }
                //one file is passed to be decrypted
                case "df" : {
                    DataMigrationEncryptionDaemon encryptionDaemon = new DataMigrationEncryptionDaemon(target,destination);
                    encryptionDaemon.decryptFile();
                    break;
                }
                //folder is passed to be encrypted
                case "efol": {
                    DataMigrationEncryptionDaemon encryptionDaemon = new DataMigrationEncryptionDaemon(target, destination);
                    encryptionDaemon.encryptFiles();
                    break;
                }

                //folder is passed to be decrypted
                case "dfol": {
                    DataMigrationEncryptionDaemon decryptionDaemon = new DataMigrationEncryptionDaemon(target, destination);
                    decryptionDaemon.decryptFiles();
                    break;
                }
                default: {
                    System.err.println("Invalid Flag");
                }
            }

        }else System.err.println("Invalid Parameters");
    }




    //Constructor
    public DataMigrationEncryptionDaemon(String inputFolder, String outputFolder) throws IOException{
    DataMigrationEncryptionDaemon.keyArn = System.getenv("keyArn");
    DataMigrationEncryptionDaemon.inputFolder = inputFolder;
    DataMigrationEncryptionDaemon.outputFolder = outputFolder;
    CRYPTOALGO = ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;
    }

    private String encrypt(String data){
        final AwsCrypto  crypto = new AwsCrypto();
        final KmsMasterKeyProvider prov = new KmsMasterKeyProvider(keyArn);
        //Amazon states that data should have a context associated with it, but the link it provides is down so  ¯\_(ツ)_/¯
        final Map<String, String> context = Collections.singletonMap("Example", "String");
        final String ciphertext = crypto.encryptString(prov,data,context).getResult();
        return ciphertext;
    }

    private String decrypt(String ciphertext){
        final Map<String, String> context = Collections.singletonMap("Example", "String");
        // Instantiate the SDK
        final AwsCrypto crypto = new AwsCrypto();
        //Set the correct algo
        crypto.setEncryptionAlgorithm(CRYPTOALGO);
        // Set up the master key provider
        final KmsMasterKeyProvider prov = new KmsMasterKeyProvider(keyArn);
        final CryptoResult<String, KmsMasterKey> decryptResult = crypto.decryptString(prov, ciphertext);
        // Check the encryption context (and ideally the master key) to
        // ensure this is the expected ciphertext
        if (!decryptResult.getMasterKeyIds().get(0).equals(keyArn)) {
            throw new IllegalStateException("Wrong key id!");
        }
        // The SDK may add information to the encryption context, so check to
        // ensure all of the values are present
        for (final Map.Entry<String, String> e : context.entrySet()) {
            if (!e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey()))) {
                throw new IllegalStateException("Wrong Encryption Context!");
            }
        }
        // The data is correct, so output it.
        //System.out.println("Decrypted: " + decryptResult.getResult());
        return decryptResult.getResult();
    }
    
    public void encryptFile() throws IOException{
        //read the file in from the path
        String fileContent = new String(Files.readAllBytes(Paths.get(inputFolder)));
        //encrypt the contents
        String  eyncriptedContent = this.encrypt(fileContent);
        String fileName = FilenameUtils.getBaseName(inputFolder) + "." + FilenameUtils.getExtension(inputFolder);
        this.createFile(outputFolder+"/"+fileName,eyncriptedContent);
        deleteFile(inputFolder);
    }


    //decrypts the file given and moves it to given directory
    //expects the file to be part of the path
    private void decryptFile() throws IOException{
        //read the file in from the path
        String fileContent = new String(Files.readAllBytes(Paths.get(inputFolder)));
        //encrypt the contents
        String  decryptedContent = this.decrypt(fileContent);
        String fileName = FilenameUtils.getBaseName(inputFolder) + "." + FilenameUtils.getExtension(inputFolder);
        this.createFile(outputFolder+"/"+fileName,decryptedContent);
        deleteFile(inputFolder);
    }

    //encrypts all files in the target folder and moves them to the output folder
    private void encryptFiles() throws IOException {
        List<File> fileList = this.getFileList();
        String fileContent;
        for(File f : fileList) {
            fileContent = new String(Files.readAllBytes(Paths.get(inputFolder+"/"+f.getName())));
            String  eyncriptedContent = this.encrypt(fileContent);
            this.createFile(outputFolder+"/"+f.getName(),eyncriptedContent);
            deleteFile(f.getPath());
        }
    }
    //decrypts all files in the target folder and moves to the output folder
    private void decryptFiles() throws IOException{
        List<File> fileList = this.getFileList();
        String fileContent ;
        for(File f : fileList) {
            fileContent = new String(Files.readAllBytes(Paths.get(inputFolder+"/"+f.getName())));
            String  decryptedContent = this.decrypt(fileContent);
            this.createFile(outputFolder+"/"+f.getName(),decryptedContent);
            deleteFile(f.getPath());
        }
    }

    //get a list of files in the in the target Folder
    private List<File> getFileList(){
        File directory = new File(inputFolder);
        List<File> fileList = new ArrayList<>();
        //get all the files from a directory
        File[] fList = directory.listFiles();
        for (File file : fList){
            if (file.isFile()){
                fileList.add(file);
                //System.out.println(file.getName());
            }
        }
        return fileList;
    }

    //deletes the file at the path
    private void deleteFile(String path){
            File f = new File(path);
            f.delete();
        }
    
    //writes a file with the given content
    private void createFile(String fileName,String content) throws IOException {
        FileWriter fw = new FileWriter(fileName);
        BufferedWriter bw = new BufferedWriter(fw);
        bw.write(content);
        bw.close();
        fw.close();
    }

}