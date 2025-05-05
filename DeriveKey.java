package com.naumtinga.command;

import org.bitcoinj.crypto.*;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.core.Base58;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.ECKey;
import com.naumtinga.command.util.CommandHelper;
import com.naumtinga.command.util.CommandUtils;
import java.security.MessageDigest;
import java.math.BigInteger;
import java.util.*;

/**
 * Custom exception class for errors during key derivation.
 */
class DeriveKeyException extends Exception {
    public DeriveKeyException(String message) {
        super(message);
    }
}

/**
 * Exception thrown when the Base58 format is invalid.
 */
class InvalidBase58FormatException extends DeriveKeyException {
    public InvalidBase58FormatException(String message) {
        super(message);
    }
}

/**
 * Exception thrown when the length of a key is invalid.
 */
class InvalidLengthException extends DeriveKeyException {
    public InvalidLengthException(String message) {
        super(message);
    }
}

/**
 * Exception thrown when the checksum of a key is invalid.
 */
class InvalidChecksumException extends DeriveKeyException {
    public InvalidChecksumException(String message) {
        super(message);
    }
}

/**
 * Exception thrown when the prefix of a key is invalid.
 */
class InvalidKeyPrefixException extends DeriveKeyException {
    public InvalidKeyPrefixException(String message) {
        super(message);
    }
}

/**
 * Exception thrown when a key value is out of the valid range.
 */
class InvalidKeyRangeException extends DeriveKeyException {
    public InvalidKeyRangeException(String message) {
        super(message);
    }
}

/**
 * Exception thrown when a key with zero depth has non-zero parent fingerprint or index.
 */
class ZeroDepthException extends DeriveKeyException {
    public ZeroDepthException(String message) {
        super(message);
    }
}

/**
 * Exception thrown when a public key is invalid.
 */
class InvalidPubKeyException extends DeriveKeyException {
    public InvalidPubKeyException(String message) {
        super(message);
    }
}

/**
 * Exception thrown when there is a mismatch between key versions (e.g., xpub vs xprv).
 */
class KeyVersionMismatchException extends DeriveKeyException {
    public KeyVersionMismatchException(String message) {
        super(message);
    }
}

/**
 * Exception thrown when the derivation path format is invalid.
 */
class InvalidPathFormatException extends DeriveKeyException {
    public InvalidPathFormatException(String message) {
        super(message);
    }
}

/**
 * Exception thrown when attempting to derive a hardened path from an xpub key.
 */
class HardenedPathFromXpubException extends DeriveKeyException {
    public HardenedPathFromXpubException(String message) {
        super(message);
    }
}

/**
 * Exception thrown when the seed format or length is invalid.
 */
class InvalidSeedException extends DeriveKeyException {
    public InvalidSeedException(String message) {
        super(message);
    }
}

/**
 * Exception thrown when the extended key version is unknown.
 */
class UnknownExtendedKeyVersionException extends DeriveKeyException {
    public UnknownExtendedKeyVersionException(String message) {
        super(message);
    }
}

/**
 * Exception thrown when the seed contains non-hexadecimal characters.
 */
class NonHexSeedException extends DeriveKeyException {
    public NonHexSeedException(String message) {
        super(message);
    }
}

/**
 * Exception thrown when an invalid argument is provided.
 */
class InvalidArgumentException extends DeriveKeyException {
    public InvalidArgumentException(String message) {
        super(message);
    }
}

/**
 * Exception thrown when a required value is missing.
 */
class MissingValueException extends DeriveKeyException {
    public MissingValueException(String message) {
        super(message);
    }
}

/**
 * Handles key derivation operations for BIP-32 compatible keys.
 * Supports deriving keys from seeds, xpub, or xprv inputs, with optional derivation paths.
 */
public class DeriveKey {
    // Constants for key lengths and indices
    private static final int VERSION_LENGTH = 4; // Length of version bytes in extended keys
    private static final int DEPTH_INDEX = 4; // Index of depth byte in extended key data
    private static final int PARENT_FINGERPRINT_LENGTH = 4; // Length of parent fingerprint bytes
    private static final int PARENT_FINGERPRINT_START = 5; // Start index of parent fingerprint
    private static final int PARENT_FINGERPRINT_END = 9; // End index of parent fingerprint
    private static final int CHILD_NUMBER_LENGTH = 4; // Length of child number bytes
    private static final int CHILD_NUMBER_START = 9; // Start index of child number
    private static final int CHILD_NUMBER_END = 13; // End index of child number
    private static final int KEY_DATA_START = 45; // Start index of key data (public or private)
    private static final int KEY_DATA_END = 78; // End index of key data
    private static final int CHECKSUM_LENGTH = 4; // Length of checksum bytes
    private static final int MIN_EXTENDED_KEY_LENGTH = 78; // Minimum length of decoded extended key
    private static final int KEY_BYTE_LENGTH = 32; // Length of private or public key bytes
    private static final int MIN_SEED_HEX_LENGTH = 32; // Minimum length of seed in hex (128 bits)
    private static final int MAX_SEED_HEX_LENGTH = 128; // Maximum length of seed in hex (512 bits)

    private static final NetworkParameters params = MainNetParams.get(); // Network parameters for Bitcoin mainnet
    private static final byte[] XPUB_VERSION = {(byte) 0x04, (byte) 0x88, (byte) 0xB2, (byte) 0x1E}; // Version bytes for xpub (MainNet)
    private static final byte[] XPRV_VERSION = {(byte) 0x04, (byte) 0x88, (byte) 0xAD, (byte) 0xE4}; // Version bytes for xprv (MainNet)
    private static final byte[] ZERO_BYTES = {0x00, 0x00, 0x00, 0x00}; // Zero bytes for parent fingerprint and child number checks
    private static final BigInteger CURVE_ORDER = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16); // Curve order for ECDSA
    private static final byte[] ZERO_KEY = new byte[KEY_BYTE_LENGTH]; // Zero key for invalid private key check

    /**
     * Main entry point for the DeriveKey command-line tool.
     * Processes command-line arguments and executes key derivation.
     *
     * @param args Command-line arguments (e.g., "derive-key <input> [--path <path>]")
     */
    public static void main(String[] args) {
        try {
            // Execute the main logic and get the exit code
            int exitCode = executeMain(args);
            // Exit with the appropriate code (0 for success, 1 for error)
            System.exit(exitCode);
        } catch (Exception e) {
            // Print unexpected errors and exit with failure code
            System.err.println("Unexpected error: " + e.getMessage());
            System.exit(1);
        }
    }

    /**
     * Executes the main logic for key derivation, validating the command.
     *
     * @param args Command-line arguments
     * @return Exit code (0 for success, 1 for failure)
     */
    public static int executeMain(String[] args) {
        try {
            // Validate the command is "derive-key"
            if (args.length < 1 || !args[0].equals("derive-key")) {
                System.err.println("Usage: java -jar <jarfile> derive-key [options] <seed/xpriv/xpub>");
                return 1;
            }
            // Extract sub-arguments (excluding the command name)
            String[] subArgs = Arrays.copyOfRange(args, 1, args.length);
            // Execute the sub-arguments and return the result
            return execute(subArgs);
        } catch (Exception e) {
            // Handle any errors during execution
            System.err.println("Error: " + e.getMessage());
            return 1;
        }
    }

    /**
     * Executes key derivation with the provided arguments, designed for test compatibility.
     * Does not throw exceptions, instead printing errors and returning an exit code.
     *
     * @param args Arguments for key derivation
     * @return Exit code (0 for success, 1 for failure)
     */
    public static int execute(String[] args) {
        try {
            // Delegate to the exception-throwing method
            return executeWithExceptions(args);
        } catch (DeriveKeyException e) {
            // Catch and print derivation-specific errors
            System.err.println("Error: " + e.getMessage());
            return 1;
        }
    }

    /**
     * Executes key derivation with the provided arguments, throwing exceptions on error.
     *
     * @param args Arguments for key derivation
     * @return Exit code (0 for success, 1 for failure)
     * @throws DeriveKeyException If an error occurs during derivation
     */
    public static int executeWithExceptions(String[] args) throws DeriveKeyException {
        // Check if help is requested (--help or -h)
        if (CommandUtils.isHelpRequested(args)) {
            CommandHelper.printDeriveKeyHelp();
            return 0;
        }

        // Initialize variables for derivation path and input
        String derivationPath = "";
        String input = null;

        // Parse command-line arguments
        for (int i = 0; i < args.length; i++) {
            if ("--path".equals(args[i])) {
                // Check if a value follows the --path option
                if (i + 1 >= args.length) {
                    throw new InvalidArgumentException("missing value for --path option");
                }
                // Set the derivation path
                derivationPath = args[i + 1];
                i++;
            } else if (!args[i].startsWith("-") && input == null) {
                // Set the input (seed, xpub, or xprv)
                input = args[i];
                // Check for invalid carriage return in input
                if (input.contains("\r")) {
                    throw new InvalidSeedException("invalid seed");
                }
            }
        }

        // Check if input should be read from stdin
        if (Arrays.asList(args).contains("-")) {
            return executeFromStdin(derivationPath);
        }

        // Ensure an input was provided
        if (input == null) {
            throw new MissingValueException("missing seed/xpriv/xpub input");
        }

        // Execute derivation with the provided input and path
        return execute(input, derivationPath);
    }

    /**
     * Executes key derivation with the specified input and derivation path.
     *
     * @param input The seed, xpub, or xprv to derive from
     * @param derivationPath The BIP-32 derivation path (e.g., "m/0/1")
     * @return Exit code (0 for success, 1 for failure)
     */
    public static int execute(String input, String derivationPath) {
        try {
            // Process the input and perform derivation
            processInput(input, derivationPath);
            return 0;
        } catch (DeriveKeyException e) {
            // Handle derivation errors
            System.err.println("Error: " + e.getMessage());
            return 1;
        }
    }

    /**
     * Executes key derivation by reading input from stdin.
     *
     * @param derivationPath The BIP-32 derivation path
     * @return Exit code (0 for success, 1 for failure)
     */
    public static int executeFromStdin(String derivationPath) {
        // Use an array to capture the exit code in the lambda
        final int[] exitCode = {0};
        // Read and process input from stdin
        CommandHelper.readAndProcessStdin("derive-key", input -> {
            try {
                // Clean the input hex seed
                String cleaned = cleanHexSeed(input);
                // Check if the input is a valid hex seed
                if (cleaned.matches("[0-9a-fA-F]+")) {
                    // Validate the seed length
                    if (!isValidSeedLength(cleaned)) {
                        throw new InvalidSeedException("seed must be between 128 and 512 bits (32 to 128 hex characters)");
                    }
                    // Validate the seed format
                    if (!isValidSeedFormat(input)) {
                        throw new InvalidSeedException("invalid seed");
                    }
                    // Derive the key from the seed
                    deriveFromSeed(cleaned, derivationPath);
                } else if (input.startsWith("xpub") || input.startsWith("xprv")) {
                    // Derive the key from an extended key (xpub or xprv)
                    deriveFromExtendedKey(input, derivationPath);
                } else {
                    // Handle non-hexadecimal input
                    throw new NonHexSeedException("non-hexadecimal seed value '" + input + "'");
                }
            } catch (DeriveKeyException e) {
                // Handle errors during derivation
                System.err.println("Error: " + e.getMessage());
                exitCode[0] = 1;
            }
        });
        return exitCode[0];
    }

    /**
     * Processes the input to determine the type (seed, xpub, or xprv) and perform derivation.
     *
     * @param input The seed, xpub, or xprv
     * @param derivationPath The BIP-32 derivation path
     * @throws DeriveKeyException If an error occurs during processing
     */
    private static void processInput(String input, String derivationPath) throws DeriveKeyException {
        // Check if the input is an extended key (xpub or xprv)
        if (input.startsWith("xpub") || input.startsWith("xprv")) {
            deriveFromExtendedKey(input, derivationPath);
            return;
        }

        // Clean the input hex seed
        String cleaned = cleanHexSeed(input);
        // Check if the input is a valid hex string
        if (cleaned.matches("[0-9a-fA-F]+")) {
            // Validate the seed length
            if (!isValidSeedLength(cleaned)) {
                throw new InvalidSeedException("seed must be between 128 and 512 bits (32 to 128 hex characters)");
            }
            // Validate the seed format
            if (!isValidSeedFormat(input)) {
                throw new InvalidSeedException("invalid seed");
            }
            // Derive the key from the seed
            deriveFromSeed(cleaned, derivationPath);
        } else {
            // Handle unknown key versions
            throw new UnknownExtendedKeyVersionException("unknown extended key version");
        }
    }

    /**
     * Derives a key from a hex seed using the specified derivation path.
     *
     * @param hexSeed The hex-encoded seed
     * @param path The BIP-32 derivation path
     * @throws DeriveKeyException If an error occurs during derivation
     */
    private static void deriveFromSeed(String hexSeed, String path) throws DeriveKeyException {
        // Convert the hex seed to bytes
        byte[] seedBytes = hexStringToByteArray(hexSeed);
        // Create the master private key from the seed
        DeterministicKey key = HDKeyDerivation.createMasterPrivateKey(seedBytes);

        // Parse the derivation path into child numbers
        List<ChildNumber> parsedPath = path.isEmpty() ? Collections.emptyList() : parsePath(path);
        // Derive the child key for each path component
        for (ChildNumber child : parsedPath) {
            key = HDKeyDerivation.deriveChildKey(key, child.getI());
        }

        // Output the derived public and private keys in Base58 format
        System.out.println(key.serializePubB58(params) + ":" + key.serializePrivB58(params));
    }

    /**
     * Derives a key from an extended key (xpub or xprv) using the specified derivation path.
     *
     * @param xkey The extended key (xpub or xprv)
     * @param path The BIP-32 derivation path
     * @throws DeriveKeyException If an error occurs during derivation
     */
    private static void deriveFromExtendedKey(String xkey, String path) throws DeriveKeyException {
        DeterministicKey key;
        byte[] decoded;
        // Decode the Base58-encoded extended key
        try {
            decoded = Base58.decode(xkey);
        } catch (IllegalArgumentException e) {
            throw new InvalidBase58FormatException("invalid base58 format");
        }

        // Check if the decoded key meets the minimum length requirement
        if (decoded.length < MIN_EXTENDED_KEY_LENGTH) {
            throw new InvalidLengthException("invalid length - too short");
        }

        // Split the decoded data into the key data and checksum
        byte[] data = Arrays.copyOfRange(decoded, 0, decoded.length - CHECKSUM_LENGTH);
        byte[] checksum = Arrays.copyOfRange(decoded, decoded.length - CHECKSUM_LENGTH, decoded.length);
        // Compute the expected checksum for validation
        byte[] computedChecksum = Arrays.copyOfRange(Sha256Hash.hashTwice(data), 0, CHECKSUM_LENGTH);

        // Validate the checksum
        // Correction for Static analysis
        if (!MessageDigest.isEqual(checksum, computedChecksum)) {
            throw new InvalidChecksumException("invalid checksum");
        }

        // Extract version bytes
        byte[] version = Arrays.copyOfRange(data, 0, VERSION_LENGTH);
        // Extract depth byte
        byte depth = data[DEPTH_INDEX];
        // Extract parent fingerprint bytes
        byte[] parentFingerprint = Arrays.copyOfRange(data, PARENT_FINGERPRINT_START, PARENT_FINGERPRINT_END);
        // Extract child number bytes
        byte[] childNumber = Arrays.copyOfRange(data, CHILD_NUMBER_START, CHILD_NUMBER_END);
        // Extract key bytes (public or private key)
        byte[] keyBytes = Arrays.copyOfRange(data, KEY_DATA_START, KEY_DATA_END);

        // Validate version bytes for xpub
        if (xkey.startsWith("xpub")) {
            if (!Arrays.equals(version, XPUB_VERSION)) {
                // Format the version byte as a hex string for error reporting
                String prefixHex = String.format("%02x", version[0]);
                throw new InvalidKeyPrefixException("invalid pubkey prefix " + prefixHex);
            }
        } else if (xkey.startsWith("xprv")) {
            // Validate version bytes for xprv
            if (!Arrays.equals(version, XPRV_VERSION)) {
                // Format the version byte as a hex string for error reporting
                String prefixHex = String.format("%02x", version[0]);
                throw new InvalidKeyPrefixException("invalid prvkey prefix " + prefixHex);
            }
            // Extract the private key bytes
            // Added check after static analysis
            if (keyBytes.length < KEY_BYTE_LENGTH + 1) throw new InvalidLengthException("invalid private key length");
            byte[] privKeyBytes = keyBytes;
            byte[] keyValue;
            // Handle the leading zero byte for private keys
            if (privKeyBytes[0] == 0) {
                keyValue = Arrays.copyOfRange(privKeyBytes, 1, KEY_BYTE_LENGTH + 1);
            } else {
                keyValue = Arrays.copyOfRange(privKeyBytes, 0, KEY_BYTE_LENGTH);
            }
            // Check if the private key is zero (invalid)
            if (Arrays.equals(keyValue, ZERO_KEY)) {
                throw new InvalidKeyRangeException("private key 0 not in 1..n-1");
            }
            // Convert the private key to a BigInteger for range checking
            BigInteger privKey = new BigInteger(1, keyValue);
            // Ensure the private key is within the valid range
            if (privKey.compareTo(CURVE_ORDER) >= 0) {
                throw new InvalidKeyRangeException("private key n not in 1..n-1");
            }
        }

        // Validate depth zero constraints
        if (depth == 0) {
            // Check if parent fingerprint is non-zero at depth 0
            if (!Arrays.equals(parentFingerprint, ZERO_BYTES)) {
                throw new ZeroDepthException("zero depth with non-zero parent fingerprint");
            }
            // Check if child number is non-zero at depth 0
            if (!Arrays.equals(childNumber, ZERO_BYTES)) {
                throw new ZeroDepthException("zero depth with non-zero index");
            }
        }

        // Deserialize the extended key
        try {
            key = DeterministicKey.deserializeB58(xkey, params);
            // Additional validation for xpub keys
            if (xkey.startsWith("xpub")) {
                // Validate the public key point
                LazyECPoint point = new LazyECPoint(ECKey.CURVE.getCurve(), keyBytes);
                try {
                    point.get();
                } catch (IllegalStateException e) {
                    // Format the public key bytes as hex for error reporting
                    String pubKeyHex = bytesToHex(keyBytes).toLowerCase(Locale.ENGLISH);
                    throw new InvalidPubKeyException("invalid pubkey " + pubKeyHex);
                }
            }
        } catch (IllegalArgumentException e) {
            // Handle deserialization errors
            String errorMsg = e.getMessage() != null ? e.getMessage() : "Unknown error.";
            if (xkey.startsWith("xpub") && errorMsg.equals("Invalid point compression")) {
                // Handle invalid public key compression
                String pubKeyHex = bytesToHex(keyBytes).toLowerCase(Locale.ENGLISH);
                throw new InvalidPubKeyException("invalid pubkey " + pubKeyHex);
            } else if (xkey.startsWith("xpub") && errorMsg.contains("0000000000000000000000000000000000000000000000000000000000000000")) {
                // Handle mismatch between xpub and private key
                throw new KeyVersionMismatchException("pubkey version / prvkey mismatch");
            }
            // Extract prefix from error message for invalid key prefixes
            java.util.regex.Pattern prefixPattern = java.util.regex.Pattern.compile("^[0-9a-fA-F]{2}");
            java.util.regex.Matcher prefixMatcher = prefixPattern.matcher(errorMsg);
            if ((xkey.startsWith("xpub") || xkey.startsWith("xprv")) && prefixMatcher.find()) {
                // Handle invalid key prefix
                String prefix = prefixMatcher.group().toLowerCase(Locale.ENGLISH);
                String keyType = xkey.startsWith("xpub") ? "pubkey" : "prvkey";
                throw new InvalidKeyPrefixException("invalid " + keyType + " prefix " + prefix);
            } else if (xkey.startsWith("xprv") && errorMsg.contains("private key exceeds 32 bytes")) {
                // Handle private key size issues
                java.util.regex.Pattern bitsPattern = java.util.regex.Pattern.compile("private key exceeds 32 bytes: (\\d+) bits");
                java.util.regex.Matcher bitsMatcher = bitsPattern.matcher(errorMsg);
                if (bitsMatcher.find()) {
                    // Calculate the prefix value based on bit length
                    int bits = Integer.parseInt(bitsMatcher.group(1));
                    if (bits == 258) {
                        throw new KeyVersionMismatchException("prvkey version / pubkey mismatch");
                    } else {
                        int prefixValue = bits - 256;
                        if (bits > 258) {
                            prefixValue += 1;
                        }
                        String prefixHex = String.format("%02x", prefixValue);
                        throw new InvalidKeyPrefixException("invalid prvkey prefix " + prefixHex);
                    }
                } else {
                    throw new KeyVersionMismatchException("prvkey version / pubkey mismatch");
                }
            } else if (xkey.startsWith("xprv") && errorMsg.contains("private key exceeds")) {
                // Handle general private key size issues
                throw new KeyVersionMismatchException("prvkey version / pubkey mismatch");
            } else if (errorMsg.contains("zero depth with non-zero parent fingerprint")) {
                // Handle zero depth validation errors
                throw new ZeroDepthException("zero depth with non-zero parent fingerprint");
            }
            // General invalid key format error
            throw new DeriveKeyException("invalid key format: " + errorMsg);
        }

        // Validate key type consistency
        if (xkey.startsWith("xpub") && key.hasPrivKey()) {
            throw new KeyVersionMismatchException("pubkey version / prvkey mismatch");
        } else if (xkey.startsWith("xprv") && !key.hasPrivKey()) {
            throw new KeyVersionMismatchException("prvkey version / pubkey mismatch");
        }

        // Parse the derivation path
        List<ChildNumber> parsedPath = path.isEmpty() ? Collections.emptyList() : parsePath(path);
        // Derive the child key for each path component
        for (ChildNumber child : parsedPath) {
            // Check for hardened derivation from xpub
            if (child.isHardened() && !key.hasPrivKey()) {
                throw new HardenedPathFromXpubException("cannot derive hardened path from xpub");
            }
            key = HDKeyDerivation.deriveChildKey(key, child.getI());
        }

        // Output the derived public and private keys (or empty private key if xpub)
        System.out.println(key.serializePubB58(params) +
                (key.hasPrivKey() ? ":" + key.serializePrivB58(params) : ":"));
    }

    /**
     * Parses a BIP-32 derivation path into a list of child numbers.
     *
     * @param path The derivation path (e.g., "m/0/1")
     * @return List of child numbers
     * @throws DeriveKeyException If the path format is invalid
     */
    private static List<ChildNumber> parsePath(String path) throws DeriveKeyException {
        try {
            // Check for trailing slash in the path
            if (path.charAt(path.length() - 1) == '/') {
                throw new InvalidPathFormatException("invalid path format: " + path);
            }

            // Normalize the path by replacing 'h' or 'H' with apostrophe

            String normalizedPath = path.replaceAll("[Hh]", "'");
            // Handle empty path
            if (normalizedPath.isEmpty()) {
                return Collections.emptyList();
            }

            // Remove leading slash if present
            if (normalizedPath.charAt(0) == '/') {
                normalizedPath = normalizedPath.substring(1);
            }

            // Split the path into components
            String[] parts = normalizedPath.split("/");
            List<ChildNumber> childNumbers = new ArrayList<>();

            // Process each path component
            for (String part : parts) {
                // Check for empty components
                if (part.isEmpty()) {
                    throw new InvalidPathFormatException("invalid path format: " + path);
                }
                // Check if the component is hardened (ends with apostrophe)
                boolean hardened = part.endsWith("'");
                // Extract the number part
                String numStr = hardened ? part.substring(0, part.length() - 1) : part;
                int number;
                // Parse the number
                try {
                    number = Integer.parseInt(numStr);
                } catch (NumberFormatException e) {
                    throw new InvalidPathFormatException("invalid path format: " + path);
                }
                // Check for negative numbers
                if (number < 0) {
                    throw new InvalidPathFormatException("path number cannot be negative: " + path);
                }
                // Add the child number to the list
                childNumbers.add(new ChildNumber(number, hardened));
            }

            return childNumbers;
        } catch (Exception e) {
            // Handle general parsing errors
            throw new InvalidPathFormatException("invalid path format: " + path);
        }
    }

    /**
     * Converts a hex string to a byte array.
     *
     * @param s The hex string
     * @return The byte array
     */
    private static byte[] hexStringToByteArray(String s) {
        // Get the length of the hex string
        int len = s.length();
        // Allocate a byte array for the result
        byte[] data = new byte[len / 2];
        // Convert each pair of hex digits to a byte
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Converts a byte array to a hex string.
     *
     * @param bytes The byte array
     * @return The hex string
     */
    private static String bytesToHex(byte[] bytes) {
        // Use a StringBuilder to build the hex string
        StringBuilder sb = new StringBuilder();
        // Convert each byte to a two-digit hex representation
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Validates the length of a hex seed.
     *
     * @param hex The hex seed string
     * @return True if the length is valid, false otherwise
     */
    private static boolean isValidSeedLength(String hex) {
        // Get the length of the hex string
        int len = hex.length();
        // Check if the length is even and within the valid range
        return len % 2 == 0 && len >= MIN_SEED_HEX_LENGTH && len <= MAX_SEED_HEX_LENGTH;
    }

    /**
     * Validates the format of a seed string.
     *
     * @param input The seed string
     * @return True if the format is valid, false otherwise
     */
    private static boolean isValidSeedFormat(String input) {
        // Remove quotes from the input
        String trimmed = CommandUtils.stripQuotes(input);
        // Check for carriage returns
        if (trimmed.contains("\r")) {
            return false;
        }
        // Check if the input contains only hex characters, spaces, or tabs
        if (!trimmed.matches("[0-9a-fA-F\\s\\t]+")) {
            return false;
        }
        // Split the input by spaces or tabs
        String[] parts = trimmed.split("[\\s\\t]+");
        // Validate each part
        for (String part : parts) {
            // Skip empty parts
            if (part.length() == 0) continue;
            // Check for single hex digits
            if (part.length() == 1) {
                return false;
            }
            // Check if the part is a valid hex string
            if (!part.matches("[0-9a-fA-F]+")) {
                return false;
            }
        }
        return true;
    }

    /**
     * Cleans a hex seed by removing quotes, spaces, tabs, and carriage returns.
     *
     * @param s The hex seed string
     * @return The cleaned hex string
     */
    private static String cleanHexSeed(String s) {
        // Remove quotes from the input
        s = CommandUtils.stripQuotes(s);
        // Remove tabs, spaces, and carriage returns
        return s.replace("\\t", "").replaceAll("[\\s\\t\\r]", "");
    }
}