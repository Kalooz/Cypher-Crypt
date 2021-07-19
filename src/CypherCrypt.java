import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.*;
import java.util.stream.Collectors;

public class CypherCrypt {

    private static final String passwordFileCipher = System.getProperty("user.dir") + "\\passwords.cipher";
    private static final String IVFile = System.getProperty("user.dir") + "\\outputIV";
    private static String masterPass;
    private static final String salt = "salt";
    private static String s = "";
    private static Map<String, UserInfo> map = new HashMap<>();
    private static String cipherString = "";
    private static Boolean logedIn = false;
    private static final String border = "----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------";
    private static final BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
    private static final SecureRandom random = new SecureRandom();

    private static final String Lowercase = "abcdefghijklmnopqrstuvwxyz";
    private static final String Uppercase = Lowercase.toUpperCase();
    private static final String Digits = "0123456789";
    private static final String Puncuation = "!@#&()[{}]:;',?/*~$^+=<>";
    private static final String AllCharacters = Lowercase + Uppercase + Digits + Puncuation;


    public static void main(String args[]) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InterruptedException {

        clearConsole();
        Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
            public void run() {
                System.out.println("Saved Securely");
            }
        }, "Shutdown-thread"));

        File pass = new File(passwordFileCipher);
        File iv = new File(IVFile);
        if (pass.exists() && iv.exists()) {

            logIn();
            clearConsole();
            mainMenu();
        } else if (!pass.exists()) {
            System.out.print("Create Password: ");
            masterPass = reader.readLine();
            clearConsole();
            mainMenu();
        }
    }

    public static void logIn() throws IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException {
        while (!logedIn) {
            System.out.print("\nEnter Password: ");
            masterPass = reader.readLine();
            decrypt();
        }
    }

    public static void mainMenu() throws IOException, InterruptedException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException {

        String mainMenu = ("\n1. New Account \n2. Lookup Account \n3. View All Passwords \n4. Remove Account\n5. Close\n");
        System.out.println(mainMenu);

        String input = reader.readLine();
        if (input.equals("1")) {
            clearConsole();
            newAccount();
            clearConsole();
            mainMenu();
        }

        if (input.equals("2")) {
            clearConsole();
            findApp();
            clearConsole();
            mainMenu();
        }

        if (input.equals("3")) {
            clearConsole();
            printAllPassword();
            clearConsole();
            mainMenu();
        }

        if (input.equals("4")) {
            clearConsole();
            deleteAccount();
            clearConsole();
            mainMenu();
        }

        if (input.equals("5")) {
            clearConsole();
            encrypt();
            System.exit(0);
        } else {
            clearConsole();
            System.out.println("Invalid Input");
            mainMenu();
        }
    }

    public static SecretKey generateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(masterPass.toCharArray(), salt.getBytes(), 65536, 256);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        return secret;
    }

    public static void decrypt() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, InvalidAlgorithmParameterException {

        try (FileInputStream in = new FileInputStream(passwordFileCipher)) {

            byte[] iv = new byte[16];
            try {
                FileInputStream inFile = new FileInputStream(IVFile);
                int bytesRead;
                if ((bytesRead = inFile.read(iv)) != -1) {
                    if (bytesRead != 16) {
                        System.out.println("ERROR: Expected reading " + 16 + "bytes but found " + bytesRead + "bytes in the file: " + IVFile);
                        System.exit(0);

                    }
                }
            } catch (Exception e) {
                System.out.println("Couldn't read IV file");
                System.exit(0);
            }

            SecretKey secret = generateKey();

            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * 8, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

            cipher.init(Cipher.DECRYPT_MODE, secret, gcmParameterSpec);
            s = "";
            byte[] obuf;
            byte[] ibuf = new byte[1024];
            int len;
            while ((len = in.read(ibuf)) != -1) {
                obuf = cipher.update(ibuf, 0, len);
                if (obuf != null) {
                    String g = new String(obuf, StandardCharsets.UTF_8);
                    s += g;
                }
            }
            obuf = cipher.doFinal();
            if (obuf != null) {
                String z = new String(obuf, StandardCharsets.UTF_8);
                s += z;
            }
            in.close();
            String[] ary = s.split(" ");
            for (int i = 0; i < ary.length - 2; i += 3) {
                map.put(ary[i], new UserInfo(ary[i + 1], ary[i + 2]));
            }
            logedIn = true;

        } catch (IOException | IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            clearConsole();
            System.out.println("Incorrect Password");
            logIn();
        }
    }

    public static void encrypt() throws NoSuchAlgorithmException, IOException, InvalidKeyException, InvalidKeySpecException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {

        byte[] iv = new byte[16];
        random.nextBytes(iv);

        try {
            FileOutputStream outputFile = new FileOutputStream(IVFile);
            outputFile.write(iv);
            outputFile.close();
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("ERROR: Couldn't write to IVFile");
        }

        SecretKey secret = generateKey();
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * 8, iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        cipher.init(Cipher.ENCRYPT_MODE, secret, gcmParameterSpec);

        map.entrySet().forEach(entry -> {
            cipherString += (entry.getKey() + " " + entry.getValue().getUser() + " " + entry.getValue().getPass() + " ");
        });

        FileOutputStream out = new FileOutputStream(passwordFileCipher);
        byte[] buf = new byte[1024];
        int len;
        ByteArrayInputStream in = new ByteArrayInputStream(cipherString.getBytes("UTF8"));
        while ((len = in.read(buf)) != -1) {
            byte[] obuf = cipher.update(buf, 0, len);
            if (obuf != null) out.write(obuf);
        }
        byte[] obuf = cipher.doFinal();
        if (obuf != null) out.write(obuf);
        out.close();
        in.close();
    }


    public static void newAccount() throws IOException, InterruptedException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeySpecException {

        String appName;
        String username;
        String password;

        System.out.print("\nEnter the app name: ");
        appName = reader.readLine();
        if (map.containsKey(appName)) {
            clearConsole();
            System.out.println("Account for app name already exists.");
            mainMenu();
        } else {
            System.out.print("Enter the username: ");
            username = reader.readLine();

            String choice;

            boolean test = true;
            while (test) {

                System.out.println("1. Generate Password\n2. Enter Password");
                choice = reader.readLine();

                if (choice.equals("1")) {
                    test = false;
                    clearConsole();
                    System.out.print("\nEnter Desired Password Length: ");
                    //int length = Integer.parseInt(reader.readLine());

                    try{
                        int length = Integer.parseInt(reader.readLine());
                        String pass = generateRandomPass(length);
                        map.put(appName.trim(), new UserInfo(username.trim(), pass.trim()));
                    }catch (NumberFormatException ex) {
                        clearConsole();
                        test = true;
                    }
                }


                if (choice.equals("2")) {
                    System.out.println("Enter Pass");
                    password = reader.readLine();
                    map.put(appName.trim(), new UserInfo(username.trim(), password.trim()));
                    test = false;
                } else {
                    clearConsole();
                    System.out.println("Invalid Input");
                }
            }
        }
    }

    private static String generateRandomPass(int passwordLength) {

        if (passwordLength < 20) {
            passwordLength = 20;
        }

        String result = "";

        for (int i = 0; i < 2; i++) {
            int index = random.nextInt(Lowercase.length());
            result += (Lowercase.charAt(index));
        }
        for (int i = 0; i < 2; i++) {
            int index = random.nextInt(Uppercase.length());
            result += (Uppercase.charAt(index));
        }
        for (int i = 0; i < 2; i++) {
            int index = random.nextInt(Digits.length());
            result += (Digits.charAt(index));
        }
        for (int i = 0; i < 2; i++) {
            int index = random.nextInt(Puncuation.length());
            result += (Puncuation.charAt(index));
        }
        for (int i = 0; i < passwordLength - 8; i++) {
            int index = random.nextInt(AllCharacters.length());
            result += (AllCharacters.charAt(index));
        }

        String password = result;

        List<String> shuffled = Arrays.asList(password.split(""));
        Collections.shuffle(shuffled);
        return shuffled.stream().collect(Collectors.joining());
    }

    public static void findApp() throws IOException, NoSuchProviderException, NoSuchAlgorithmException, NoSuchPaddingException, InterruptedException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException {

        System.out.print("\nEnter app name: ");
        String appName = reader.readLine();

        UserInfo search;
        search = map.get(appName);
        if (search == null) {
            clearConsole();
            System.out.println("\nNot Found");
            System.out.println("Press Enter to Return to Menu");
            reader.readLine();
            clearConsole();
        } else {
            clearConsole();
            printPassword(appName);

            System.out.println("\n1. Change Password\n2. Return to Menu");
            String choice;
            boolean test = true;
            while (test) {
                choice = reader.readLine();
                if (choice.equals("1")) {

                    UserInfo temp = map.get(appName);

                    while (test) {
                        clearConsole();
                        System.out.println("1. Generate Password\n2. Enter Password");
                        choice = reader.readLine();
                        if (choice.equals("1")) {
                            test = false;
                            clearConsole();
                            System.out.print("\nEnter Desired Password Length: ");
                            try{
                                int length = Integer.parseInt(reader.readLine());
                                String pass = generateRandomPass(length);
                                temp.changePass(pass);
                            }catch (NumberFormatException ex) {
                                clearConsole();
                                test = true;
                                System.out.println("Invalid Input");
                            }
                        }
                        if (choice.equals("2")) {
                            System.out.print("Enter Pass: ");
                            temp.changePass(reader.readLine());
                            test = false;
                        }

                    }
                }
                if (choice.equals("2")) {
                    clearConsole();
                    mainMenu();
                    test = false;
                } else {
                    System.out.println("Invalid Input");
                }
            }
        }
    }


    public static void deleteAccount() throws IOException, NoSuchAlgorithmException, InvalidKeyException, InterruptedException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException, NoSuchProviderException, IllegalBlockSizeException, InvalidKeySpecException {
        System.out.print("\nEnter app name: ");
        String appName = reader.readLine();
        if (map.containsKey(appName)) {
            System.out.println("\n Are you sure you want to delete?\n1. YES \n2. NO\n");
            String choice;

            boolean test = true;
            while (test) {
                choice = reader.readLine();
                if (choice.equals("1")) {
                    map.remove(appName);
                    test = false;
                }
                if (choice.equals("2")) {
                    clearConsole();
                    mainMenu();
                    test = false;
                } else {
                    System.out.println("Invalid Input");
                }
            }
        } else
            System.out.println("App not found");
    }

    public final static void clearConsole() {

        try {
            final String os = System.getProperty("os.name");

            if (os.contains("Windows")) {
                new ProcessBuilder("cmd", "/c", "cls").inheritIO().start().waitFor();
            } else {
                System.out.println("\033[H\033{2J");
                System.out.flush();
            }

            System.out.println("  ______            _                     ______                        \n" +
                    " / _____)          | |                   / _____)                  _    \n" +
                    "| /     _   _ ____ | | _   ____  ____   | /       ____ _   _ ____ | |_  \n" +
                    "| |    | | | |  _ \\| || \\ / _  )/ ___)  | |      / ___) | | |  _ \\|  _) \n" +
                    "| \\____| |_| | | | | | | ( (/ /| |      | \\_____| |   | |_| | | | | |__ \n" +
                    " \\______)__  | ||_/|_| |_|\\____)_|       \\______)_|    \\__  | ||_/ \\___)\n" +
                    "       (____/|_|                                      (____/|_|         \n" +
                    "                     Welcome to Cypher Crypt                         "
            );
        } catch (final Exception e) {
        }
    }



    private static void printPassword(String appname) {

        System.out.println("\n" + border);
        String name = "App Name";
        String p = "Password";
        String u = "User Name";

        int keyLength1 = name.length();
        int userlength1 = p.length();
        int passLength1 = u.length();

        for (int i = 0; i <= 30 - keyLength1; i += 2) {
            name = " " + name + " ";
        }

        for (int i = 0; i <= 150 - passLength1; i += 2) {
            p = " " + p + " ";
        }

        for (int i = 0; i <= 30 - userlength1; i += 2) {
            u = " " + u + " ";
        }
        System.out.println("|" + name + "|" + u + "|" + p + " |");
        System.out.println(border);


        String key = appname + " ";
        String user = map.get(appname).getUser() + " ";
        String pass = map.get(appname).getPass();

        int keyLength = key.length();
        int userlength = user.length();
        int passLength = pass.length();

        for (int i = 0; i < 30 - keyLength; i++) {
            key += " ";
        }

        for (int i = 0; i < 30 - userlength; i++) {
            user += " ";
        }

        for (int i = 0; i < 150 - passLength; i++) {
            pass += " ";
        }
        System.out.println("| " + key + " | " + user + "  | " + pass + "|");
        System.out.println(border);

    }

    private static void printAllPassword() throws IOException {

        System.out.println("\n" + border);
        String name = "App Name";
        String p = "Password";
        String u = "User Name";

        int keyLength1 = name.length();
        int userlength1 = p.length();
        int passLength1 = u.length();

        for (int i = 0; i <= 30 - keyLength1; i += 2) {
            name = " " + name + " ";
        }

        for (int i = 0; i <= 150 - passLength1; i += 2) {
            p = " " + p + " ";
        }

        for (int i = 0; i <= 30 - userlength1; i += 2) {
            u = " " + u + " ";
        }
        System.out.println("|" + name + "|" + u + "|" + p + " |");
        System.out.println(border);
        map.entrySet().forEach(entry -> {
            String key = entry.getKey() + " ";
            String user = entry.getValue().getUser() + " ";
            String pass = entry.getValue().getPass();

            int keyLength = key.length();
            int userlength = user.length();
            int passLength = pass.length();

            for (int i = 0; i < 30 - keyLength; i++) {
                key += " ";
            }

            for (int i = 0; i < 30 - userlength; i++) {
                user += " ";
            }

            for (int i = 0; i < 150 - passLength; i++) {
                pass += " ";
            }
            System.out.println("| " + key + " | " + user + "  | " + pass + "|");
            System.out.println(border);

        });
        System.out.println("Press Enter to return to menu");
        reader.readLine();
    }
}