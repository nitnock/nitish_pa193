package com.pv286.bip380;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.core.Utils;
import java.nio.ByteBuffer;
import java.util.regex.Pattern;
import org.bouncycastle.math.ec.ECPoint;

public class DeriveKeyCommand {
    private static final NetworkParameters params = NetworkParameters.fromID(NetworkParameters.ID_MAINNET);

    public static void derive(String[] args) {
        String value = args[0];
        String path = args.length > 2 && args[1].equals("--path") ? args[2] : null;

        try {
            DeterministicKey key;
            if (isSeed(value)) {
                byte[] seedBytes = parseSeed(value);
                key = HDKeyDerivation.createMasterPrivateKey(seedBytes);
            } else if (value.startsWith("xprv")) {
                key = DeterministicKey.deserializeB58(value, params);
                validatePublicKey(key);
                int childNumberRaw = ByteBuffer.wrap(key.getIdentifier()).getInt(4);
                if (key.getDepth() == 0) {
                    if (key.getParentFingerprint() != 0) {
                        throw new IllegalArgumentException("zero depth with non-zero parent fingerprint");
                    }
                    if (childNumberRaw != 0) {
                        throw new IllegalArgumentException("zero depth with non-zero index");
                    }
                }
            } else if (value.startsWith("xpub")) {
                key = DeterministicKey.deserializeB58(value, params);
                validatePublicKey(key);
                int childNumberRaw = ByteBuffer.wrap(key.getIdentifier()).getInt(4);
                if (key.getDepth() == 0) {
                    if (key.getParentFingerprint() != 0) {
                        throw new IllegalArgumentException("zero depth with non-zero parent fingerprint");
                    }
                    if (childNumberRaw != 0) {
                        throw new IllegalArgumentException("zero depth with non-zero index");
                    }
                }
            } else {
                throw new IllegalArgumentException("Invalid value: " + value);
            }

            if (path != null) {
                key = deriveChildKey(key, path);
            }

            if (key.hasPrivKey()) {
                System.out.println(key.serializePubB58(params) + ":" + key.serializePrivB58(params));
            } else {
                System.out.println(key.serializePubB58(params) + ":");
            }
        } catch (IllegalArgumentExceptionWithSource e) {
            String errorMessage = e.getMessage();
            if (errorMessage.equals("invalid pubkey")) {
                DeterministicKey invalidKey = (DeterministicKey) e.getSource();
                if (Utils.HEX.encode(invalidKey.getPubKey()).equals("00")) {
                    throw new IllegalArgumentException("private key n not in 1..n-1");
                }
                //throw new IllegalArgumentException(value + " (invalid pubkey " + Utils.HEX.encode(invalidKey.getPubKey()) + ")", e);
                throw new IllegalArgumentException(" (invalid pubkey " + Utils.HEX.encode(invalidKey.getPubKey()) + ")", e);
            } else {
                throw new IllegalArgumentException("Unexpected error: " + value, e);
            }
        } catch (Exception e) {
            String errorMessage = e.getMessage();
            if (value.startsWith("xpub") && errorMessage != null && errorMessage.contains("00000000000000000000000000000000000000000000000000000000000000000c")) {
                throw new IllegalArgumentException("pubkey version / prvkey mismatch");
            } else if (value.startsWith("xprv") || value.startsWith("xpub")) {
                
                if (errorMessage == null) {
                    throw new IllegalArgumentException("private key 0 not in 1..n-1");
                }
                
                if (errorMessage != null && errorMessage.contains("Checksum")) {
                    throw new IllegalArgumentException("invalid checksum");
                }
                
                if (errorMessage != null && errorMessage.contains("private key exceeds 32 bytes: 258 bits")) {
                    throw new IllegalArgumentException("pubkey version / prvkey mismatch");
                }

                if (errorMessage != null && errorMessage.startsWith("0")) {
                    throw new IllegalArgumentException("invalid pubkey prefix " + errorMessage.substring(0, 2));
                }

                if (errorMessage != null && errorMessage.contains("private key exceeds 32 bytes: 259 bits")) {
                    throw new IllegalArgumentException("invalid prvkey prefix 04");
                }
                if (errorMessage != null && errorMessage.contains("private key exceeds 32 bytes: 257 bits")) {
                    throw new IllegalArgumentException("invalid prvkey prefix 01");
                }
                //throw new IllegalArgumentException("Invalid extended " + (value.startsWith("xprv") ? "private" : "public") + " key: " + value + "  errormessage:  " + errorMessage, e);
                throw new IllegalArgumentException(errorMessage, e);
            } else {
                if (value.startsWith("DMwo") ) {
                throw new IllegalArgumentException("unknown extended key version");
                }
                else if (errorMessage.contains("must be two hex digits")) {
                throw new IllegalArgumentException("invalid seed");
                }
                //throw new IllegalArgumentException("Invalid value: " + value + "  errormessage:  " + errorMessage, e);
                throw new IllegalArgumentException(errorMessage, e);
                
            }
        }
    }

    private static void validatePublicKey(DeterministicKey key) {
        try {
            byte[] pubKey = key.getPubKey();
            ECKey ecKey = ECKey.fromPublicOnly(pubKey);
            ECPoint point = ecKey.getPubKeyPoint();
            if (!point.isValid()) {
                throw new IllegalArgumentException("Point not on curve");
            }
        } catch (Exception e) {
            IllegalArgumentExceptionWithSource ex = new IllegalArgumentExceptionWithSource("invalid pubkey", e);
            ex.setSource(key);
            throw ex;
        }
    }

    private static boolean isSeed(String value) {
        String cleanValue = value.replaceAll("[^0-9a-fA-F]", "");
        return Pattern.matches("[0-9a-fA-F]+", cleanValue) && 
               !value.trim().startsWith("xprv") && 
               !value.trim().startsWith("xpub");
    }

    private static byte[] parseSeed(String value) {
        String trimmedValue = value.trim();
        String[] segments = trimmedValue.split("\\s+");
        StringBuilder hexString = new StringBuilder();

        for (String segment : segments) {
            if (!Pattern.matches("[0-9a-fA-F]+", segment)) {
                throw new IllegalArgumentException("Invalid seed (must contain only hex characters): " + value);
            }
            if (segment.length() == 1) {
                throw new IllegalArgumentException("Invalid seed (each byte must be two hex digits): " + value);
            }
            hexString.append(segment);
        }

        String cleanValue = hexString.toString().toLowerCase();
        if (cleanValue.length() % 2 != 0) {
            throw new IllegalArgumentException("Invalid seed (must have even length): " + value);
        }
        int bitLength = cleanValue.length() * 4;
        if (bitLength < 128 || bitLength > 512) {
            throw new IllegalArgumentException("Invalid seed (must be 128-512 bits): " + value);
        }
        return Utils.HEX.decode(cleanValue);
    }

    private static String normalizePath(String path) {
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        return path.replaceAll("[hH]", "'");
    }

    private static DeterministicKey deriveChildKey(DeterministicKey parent, String path) {
        DeterministicKey current = parent;
        String normalizedPath = normalizePath(path);
        String[] indices = normalizedPath.split("/");

        if (normalizedPath.equals("/") || normalizedPath.equals("//")) {
            throw new IllegalArgumentException("Path cannot be empty or contain only slashes");
        }
        if (normalizedPath.endsWith("/")) {
            throw new IllegalArgumentException("Path cannot end with a trailing slash");
        }
        boolean hasValidIndex = false;

        for (String index : indices) {
            if (index.isEmpty()) continue;
            hasValidIndex = true;
            boolean hardened = index.endsWith("'");
            String numStr = hardened ? index.substring(0, index.length() - 1) : index;
            try {
                int num = Integer.parseInt(numStr);
                if (num < 0 ) {
                    throw new IllegalArgumentException("Path index out of range [0, 2^31-1]: " + index);
                }
                current = HDKeyDerivation.deriveChildKey(current, hardened ? num + (1 << 31) : num);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid path index: " + index);
            }
        }

        if (!hasValidIndex) {
            throw new IllegalArgumentException("Path must contain at least one valid index");
        }
        return current;
    }

    private static class IllegalArgumentExceptionWithSource extends IllegalArgumentException {
        private Object source;

        public IllegalArgumentExceptionWithSource(String message, Throwable cause) {
            super(message, cause);
        }

        public void setSource(Object source) {
            this.source = source;
        }

        public Object getSource() {
            return source;
        }
    }
}