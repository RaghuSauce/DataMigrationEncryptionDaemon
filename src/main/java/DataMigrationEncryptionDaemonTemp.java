import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.kms.KmsMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
import org.apache.commons.io.FilenameUtils;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

public class DataMigrationEncryptionDaemonTemp {

    //This is the ARN that will provide the key for encryption and decryption.

    private static String KEYARN;
    //the folder path that will be passed to the daemon
    private static String targetFolder;      //the folder whose files are being encrypted   -passed though CLI args[1]
    private static String outputFolder;      //the output folder that will contain the processed files -- CLI args[2]
    protected static CryptoAlgorithm CRYPTOALGO;// default algo we will be using for now, can change according to need
    private static Boolean  DeleteOnProcess = true;    //delete the target file after we are done processing it - SHOULD BE SET TO TRUE UNLESS DEBUGING

    //Constructor
    public DataMigrationEncryptionDaemonTemp(String targetFolder, String outputFolder) throws IOException {
        this.readConfig();
        DataMigrationEncryptionDaemonTemp.targetFolder = targetFolder;
        DataMigrationEncryptionDaemonTemp.outputFolder = outputFolder;

    }
    //get a list of files in the in the target Folder
    private List<File> getFileList(){
        File directory = new File(targetFolder);
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

    //reads the config file for the KEYARN and the Algo Cypher
    private void readConfig() throws IOException {

        InputStream config = this.getClass().getResourceAsStream("/config.csv");
        BufferedReader b = new BufferedReader(new InputStreamReader(config));
        KEYARN = b.readLine();
        String cryptAlgo = b.readLine();
        b.close();
        CRYPTOALGO = CryptoAlgorithm.valueOf(cryptAlgo);
    }



    //writes a file with the given content
    private void createFile(String fileName,String content) throws IOException {
        FileWriter fw = new FileWriter(fileName);
        BufferedWriter bw = new BufferedWriter(fw);
        bw.write(content);
        bw.close();
        fw.close();
    }

    //deletes the file at the path
    private void deleteFile(String path){
        if (DeleteOnProcess) {
            File f = new File(path);
            f.delete();
        }
    }
    //Encrypts the  data provided
    //Returns the encrypted String
    private String encrypt(String data){
        //log into key provider
        final AwsCrypto crypto = new AwsCrypto();
        //set the algo
        crypto.setEncryptionAlgorithm(CRYPTOALGO);
        final KmsMasterKeyProvider prov = new KmsMasterKeyProvider(KEYARN);
        //TODO map this information differently
        final Map<String, String> context = Collections.singletonMap("Example", "String");
        final String ciphertext = crypto.encryptString(prov,data,context).getResult();
        return ciphertext;
    }
    //Decrypts the data provided
    //Returns the decrypted string
    private String decrypt(String ciphertext){
        final Map<String, String> context = Collections.singletonMap("Example", "String");
        // Instantiate the SDK
        final AwsCrypto crypto = new AwsCrypto();
        //Set the correct algo
        crypto.setEncryptionAlgorithm(CRYPTOALGO);
        // Set up the master key provider
        final KmsMasterKeyProvider prov = new KmsMasterKeyProvider(KEYARN);
        final CryptoResult<String, KmsMasterKey> decryptResult = crypto.decryptString(prov, ciphertext);
        // Check the encryption context (and ideally the master key) to
        // ensure this is the expected ciphertext
        if (!decryptResult.getMasterKeyIds().get(0).equals(KEYARN)) {
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
    //encrypts the file given and moves it to given directory
    //expects the file to be part of the path
    private void encryptFile() throws IOException{
        //read the file in from the path
        String fileContent = new String(Files.readAllBytes(Paths.get(targetFolder)));
        //encrypt the contents
        String  eyncriptedContent = this.encrypt(fileContent);
        String fileName = FilenameUtils.getBaseName(targetFolder) + "." + FilenameUtils.getExtension(targetFolder);
        this.createFile(outputFolder+"/"+fileName,eyncriptedContent);
        deleteFile(targetFolder);
    }

    //decrypts the file given and moves it to given directory
    //expects the file to be part of the path
    private void decryptFile() throws IOException{
        //read the file in from the path
        String fileContent = new String(Files.readAllBytes(Paths.get(targetFolder)));
        //encrypt the contents
        String  decryptedContent = this.decrypt(fileContent);
        String fileName = FilenameUtils.getBaseName(targetFolder) + "." + FilenameUtils.getExtension(targetFolder);
        this.createFile(outputFolder+"/"+fileName,decryptedContent);
        deleteFile(targetFolder);
    }
    //encrypts all files in the target folder and moves them to the output folder
    private void encryptFiles() throws IOException {
        List<File> fileList = this.getFileList();
        String fileContent;
        for(File f : fileList) {
            fileContent = new String(Files.readAllBytes(Paths.get(targetFolder+"/"+f.getName())));
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
            fileContent = new String(Files.readAllBytes(Paths.get(targetFolder+"/"+f.getName())));
            String  decryptedContent = this.decrypt(fileContent);
            this.createFile(outputFolder+"/"+f.getName(),decryptedContent);
            deleteFile(f.getPath());
        }
    }
    public static void main(String[] args) throws IOException {
        if(args.length == 3) {
            String flag = args[0];
            String target = args[1];
            String destination = args[2];
            switch (flag) {
                //one file is passed to be encrypted
                case "ef" :{
                    DataMigrationEncryptionDaemonTemp encryptionDaemon = new DataMigrationEncryptionDaemonTemp(target,destination);
                    encryptionDaemon.encryptFile();
                    break;
                }
                //one file is passed to be decrypted
                case "df" : {
                    DataMigrationEncryptionDaemonTemp encryptionDaemon = new DataMigrationEncryptionDaemonTemp(target,destination);
                    encryptionDaemon.decryptFile();
                    break;
                }
                //folder is passed to be encrypted
                case "efol": {
                    DataMigrationEncryptionDaemonTemp encryptionDaemon = new DataMigrationEncryptionDaemonTemp(target, destination);
                    encryptionDaemon.encryptFiles();
                    break;
                }

                //folder is passed to be decrypted
                case "dfol": {
                    DataMigrationEncryptionDaemonTemp decryptionDaemon = new DataMigrationEncryptionDaemonTemp(target, destination);
                    decryptionDaemon.decryptFiles();
                    break;
                }
                default: {
                    System.err.println("Invalid Flag");
                }
            }

        }else if (args.length == 1 && args[0].equals("S")){
            // the input that the user will input
            //1 -> Change ARN number
            //2 -> Change Encryption Algorithm
            //3 -> Change both



            System.out.printf("%s\n%s\n%s\n%s\n","What would you like to do?","1)Change ARN","2)Change/View Encryption Algorithms","3)Exit");
            Scanner reader = new Scanner(System.in);
            String option;

            do{
                System.out.println("What would you like to to do?:");
                option = reader.next();
                option = option.toLowerCase();

                switch (option){
                    //TODO Add ARN validation before write
                    case "1":{
                        System.out.println("Please Enter the ARN you would Like to use:");
                        String newARN= reader.next();
                        System.out.println("Setting ARN to " + newARN);
                        System.out.println("Are you sure?");
                        String response = reader.next().toLowerCase();
                        if(response == "yes" || response == "y"){
                            //do something
                        }else{
                            System.out.println("ARN is unchanged");
                        }
                        //end of case1
                        break;

                    }

                    //Change the encryption Algorithm
                    case "2":
                    {


                        break;
                    }

                    //Exit the query
                    case"exit":
                    case "3": {
                        System.out.println("exiting");
                        return;
                    }
                    default:{
                        System.out.println("invalid input");
                        break;
                    }

                }
            }while(true);
        }else System.err.println("Invalid Parameters");

    }
    //TODO read folder locations from enviroment varivables
    //TODO build (maven/gradle)  and test on ec2 intance
    //TODO add to pentaho process, add file dateTime and name modifiers to the file,
    //TODO document better so others can understand
    //TODO exceptionHandling
    //TODO try to lock user perm (ie chmod ) while this is running
    //TODO move to External logging system
    //TODO check how JVM's layer, will this run in pentaho safley
}
