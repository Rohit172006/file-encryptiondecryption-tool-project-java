import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Scanner;

public class CryptoTool {

    private static final String ALGORITHM = "AES";
    
    // We use standard AES. For higher security in production, AES/CBC/PKCS5Padding with an Initialization Vector (IV) is recommended.
    private static final String TRANSFORMATION = "AES"; 

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=========================================");
        System.out.println("   File Encryption & Decryption Tool   ");
        System.out.println("=========================================");

        while (true) {
            System.out.println("\nSelect an option:");
            System.out.println("1. Encrypt a file");
            System.out.println("2. Decrypt a file");
            System.out.println("3. Exit");
            System.out.print("Your choice: ");
            
            int choice = scanner.nextInt();
            scanner.nextLine(); // Consume newline

            if (choice == 3) {
                System.out.println("Exiting program. Goodbye!");
                break;
            }

            if (choice != 1 && choice != 2) {
                System.out.println("Invalid choice. Please try again.");
                continue;
            }

            System.out.print("Enter the path of the input file: ");
            String inputFilePath = scanner.nextLine();
            File inputFile = new File(inputFilePath);

            if (!inputFile.exists() || !inputFile.isFile()) {
                System.out.println("Error: The specified file does not exist.");
                continue;
            }

            System.out.print("Enter the path for the output file: ");
            String outputFilePath = scanner.nextLine();
            File outputFile = new File(outputFilePath);

            System.out.print("Enter your secret password: ");
            String password = scanner.nextLine();

            try {
                if (choice == 1) {
                    processFile(Cipher.ENCRYPT_MODE, password, inputFile, outputFile);
                    System.out.println("\n✅ File successfully encrypted to: " + outputFile.getAbsolutePath());
                } else {
                    processFile(Cipher.DECRYPT_MODE, password, inputFile, outputFile);
                    System.out.println("\n✅ File successfully decrypted to: " + outputFile.getAbsolutePath());
                }
            } catch (Exception e) {
                System.out.println("\n❌ An error occurred during the process.");
                System.out.println("Error details: " + e.getMessage());
                if (choice == 2) {
                    System.out.println("Note: Decryption errors often happen if the password is wrong or the file is corrupted.");
                }
            }
        }
        scanner.close();
    }

    /**
     * Processes the file by either encrypting or decrypting it via a chunked stream.
     */
    private static void processFile(int cipherMode, String password, File inputFile, File outputFile) throws Exception {
        // 1. Generate a secure AES key from the user's password
        SecretKeySpec secretKey = generateKey(password);

        // 2. Initialize the Cipher
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(cipherMode, secretKey);

        // 3. Process the file via streams to prevent OutOfMemory errors on large files
        try (FileInputStream inputStream = new FileInputStream(inputFile);
             FileOutputStream outputStream = new FileOutputStream(outputFile);
             CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher)) {

            byte[] buffer = new byte[8192]; // 8KB buffer
            int bytesRead;

            while ((bytesRead = inputStream.read(buffer)) != -1) {
                cipherOutputStream.write(buffer, 0, bytesRead);
            }
        }
    }

    /**
     * Hashes the password using SHA-256 and truncates it to 16 bytes to form a valid 128-bit AES key.
     */
    private static SecretKeySpec generateKey(String password) throws Exception {
        byte[] keyBytes = password.getBytes("UTF-8");
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        keyBytes = sha.digest(keyBytes);
        
        // Use only the first 16 bytes (128 bits) for AES-128
        keyBytes = Arrays.copyOf(keyBytes, 16); 
        
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }
}