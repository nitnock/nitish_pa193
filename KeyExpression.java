package com.naumtinga.command;

import com.naumtinga.command.util.CommandHelper;
import com.naumtinga.command.util.CommandUtils;
import com.naumtinga.command.exception.KeyExpressionException;
import org.bitcoinj.core.Base58;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.params.MainNetParams;

/**
 * KeyExpression is responsible for parsing, validating, and handling key expressions used in BIP 380-style CLI tools.
 * It supports extended keys, hex public keys, WIF private keys, and key origins with derivation paths.
 */
public class KeyExpression {
    private static final NetworkParameters params = MainNetParams.get();
    private static final int MAX_NON_HARDENED_INDEX = Integer.MAX_VALUE;
    private static final long MIN_HARDENED_INDEX = ((long) Integer.MAX_VALUE) + 1;

    /**
     * Entry point for executing a key expression via CLI argument array.
     *
     * @param args command-line arguments
     * @return exit code (0 on success, 1 on failure)
     * @throws KeyExpressionException if validation or parsing fails
     */
    public static int execute(String[] args) throws KeyExpressionException {
        if (CommandUtils.isHelpRequested(args)) {
            CommandHelper.printKeyExpressionHelp();
            return 0;
        }

        if (args.length == 1 && args[0].equals("-")) {
            return executeFromStdin();
        } else if (args.length == 0) {
            throw new KeyExpressionException.InvalidArgumentsException("Missing key expression");
        } else {
            return execute(args[0]);
        }
    }

    /**
     * Executes a single key expression string.
     *
     * @param expr the key expression string
     * @return exit code (0 on success, 1 on failure)
     * @throws KeyExpressionException if validation or parsing fails
     */
    public static int execute(String expr) throws KeyExpressionException {
        if (!processSingleExpression(expr)) {
            return 1;
        }
        return 0;
    }

    /**
     * Reads and processes a key expression from standard input.
     *
     * @return exit code (0 on success)
     * @throws KeyExpressionException if parsing fails
     */
    public static int executeFromStdin() throws KeyExpressionException {
        try {
            CommandHelper.readAndProcessStdin("key-expression", input -> {
                try {
                    processSingleExpression(input);
                } catch (KeyExpressionException e) {
                    throw new RuntimeException(e); // Wrap for lambda
                }
            });
            return 0;
        } catch (RuntimeException e) {
            if (e.getCause() instanceof KeyExpressionException) {
                throw (KeyExpressionException) e.getCause();
            }
            throw new KeyExpressionException("Error processing stdin input: " + e.getMessage());
        }
    }

    /**
     * Validates and prints a single expression.
     *
     * @param expr the key expression
     * @return true if valid
     * @throws KeyExpressionException if the expression is invalid
     */
    private static boolean processSingleExpression(String expr) throws KeyExpressionException {
        expr = expr.trim();

        if (!isValidExpression(expr)) {
            throw new KeyExpressionException.InvalidExpressionException("Invalid key expression");
        }

        System.out.println(expr);
        return true;
    }

    /**
     * Validates the key expression syntax and structure.
     *
     * @param expr the key expression
     * @return true if valid
     * @throws KeyExpressionException if invalid
     */
    private static boolean isValidExpression(String expr) throws KeyExpressionException {
        if (!isValidOriginAndPath(expr)) {
            return false;
        }

        String actualKey = extractActualKey(expr);
        boolean isWIF = isValidWIF(actualKey);
        boolean isExtended = isValidExtendedKey(actualKey);
        boolean isHexPubKey = isValidHexPublicKey(actualKey);

        int slashIndex = expr.indexOf("/");
        boolean hasDerivationAfterKey = slashIndex != -1 && slashIndex >= actualKey.length();

        if (isWIF && hasDerivationAfterKey) {
            throw new KeyExpressionException.InvalidExpressionException("WIF keys cannot have derivation paths");
        }

        if (isExtended && hasDerivationAfterKey) {
            String path = expr.substring(slashIndex + 1);
            String[] steps = path.split("/");
            for (String step : steps) {
                if (step.isEmpty()) continue;
                if (step.equals("*") || step.equals("*h")) continue;
                boolean isHardened = step.endsWith("h") || step.endsWith("'");
                String numPart = isHardened ? step.substring(0, step.length() - 1) : step;
                try {
                    long index = Long.parseLong(numPart);
                    if (isHardened) {
                        if (index < 0 || index >= MIN_HARDENED_INDEX) {
                            throw new KeyExpressionException.InvalidDerivationPathException("Hardened index out of range: " + step);
                        }
                    } else {
                        if (index < 0 || index > MAX_NON_HARDENED_INDEX) {
                            throw new KeyExpressionException.InvalidDerivationPathException("Non-hardened index out of range: " + step);
                        }
                    }
                } catch (NumberFormatException e) {
                    throw new KeyExpressionException.InvalidDerivationPathException("Invalid derivation index: " + step);
                }
            }
        }

        if (!isWIF && !isExtended && !isHexPubKey) {
            throw new KeyExpressionException.InvalidExpressionException("Key is neither a valid WIF, extended key, nor hex public key");
        }

        return true;
    }

    /**
     * Extracts the base key (e.g., xpub/xprv or hex pubkey) from the expression.
     *
     * @param expr the expression
     * @return the raw key string
     * @throws KeyExpressionException if origin is malformed
     */
    private static String extractActualKey(String expr) throws KeyExpressionException {
        if (expr.startsWith("[")) {
            int closing = expr.indexOf("]");
            if (closing == -1) {
                throw new KeyExpressionException.InvalidExpressionException("Unclosed origin bracket");
            }
            if (closing >= expr.length() - 1) {
                throw new KeyExpressionException.InvalidExpressionException("Empty key after origin");
            }
            expr = expr.substring(closing + 1);
        }

        int slash = expr.indexOf("/");
        if (slash != -1) {
            expr = expr.substring(0, slash);
        }

        return expr;
    }

    private static boolean isValidHexPublicKey(String key) {
        return key.matches("02[0-9a-fA-F]{64}") ||  // Compressed pubkey
                key.matches("03[0-9a-fA-F]{64}") ||
                key.matches("04[0-9a-fA-F]{128}");  // Uncompressed pubkey
    }

    private static boolean isValidWIF(String wif) {
        try {
            byte[] decoded = Base58.decodeChecked(wif);
            return (decoded.length == 33 && decoded[0] == (byte) 0x80) ||
                    (decoded.length == 34 && decoded[0] == (byte) 0x80 && decoded[33] == 0x01);
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean isValidExtendedKey(String key) {
        try {
            DeterministicKey.deserializeB58(key, params);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Validates the origin bracket and derivation path format (if present).
     *
     * @param expr the full key expression
     * @return true if the structure is syntactically correct
     * @throws KeyExpressionException if any structural component is malformed
     */
    private static boolean isValidOriginAndPath(String expr) throws KeyExpressionException {
        String origin = "";
        String rest = expr;

        if (expr.startsWith("[")) {
            int closingIndex = expr.indexOf("]");
            if (closingIndex == -1) {
                throw new KeyExpressionException.InvalidExpressionException("Unclosed origin bracket");
            }
            origin = expr.substring(1, closingIndex);
            rest = expr.substring(closingIndex + 1);

            if (!origin.matches("[0-9a-fA-F]{8}(?:/[0-9]+[h']?)*")) {
                throw new KeyExpressionException.InvalidExpressionException("Invalid origin format");
            }
        }

        int firstSlash = rest.indexOf("/");
        if (firstSlash != -1) {
            String path = rest.substring(firstSlash + 1);
            if (!path.matches("(?:[0-9]+[h']?/?)*(\\*h?)?")) {
                throw new KeyExpressionException.InvalidDerivationPathException("Invalid derivation path format");
            }

            if (path.contains("H") || path.contains("f") || path.contains("aa")) {
                throw new KeyExpressionException.InvalidDerivationPathException("Invalid characters in derivation path");
            }
        }

        return true;
    }
}
