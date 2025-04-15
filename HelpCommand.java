package com.pv286.bip380;

public class HelpCommand {
    public static void display() {
        System.out.println("Usage: bip380 <sub-command> [options] [arguments]");
        System.out.println("BIP 32/380 key and descriptor utility.");
        System.out.println();
        System.out.println("Sub-commands:");
        System.out.println("  derive-key {value} [--path {path}] [-]");
        System.out.println("    Derive keys from seed (128-512 bits hex), xpub, or xprv.");
        System.out.println("    --path: Derivation path (e.g., /0/1h).");
        System.out.println("    -: Read value from stdin.");
        System.out.println("    Output: {xpub}:{xprv} or {xpub}: if no private key.");
        System.out.println("    Example: bip380 derive-key xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8 --path /0/1h");
        System.out.println();
        System.out.println("  key-expression {expr} [-]");
        System.out.println("    Parse and echo a BIP 380 key expression if valid.");
        System.out.println("    Supports hex public keys (02/03/04 prefix), WIF private keys (compressed/uncompressed),");
        System.out.println("    and extended keys (xpub/xprv) with optional origin and path.");
        System.out.println("    -: Read expression from stdin.");
        System.out.println("    Example: bip380 key-expression L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1");
        System.out.println();
        System.out.println("  script-expression {expr} [--verify-checksum | --compute-checksum] [-]");
        System.out.println("    Process a BIP 380 script expression (e.g., pk(), pkh(), multi(), sh(), raw()).");
        System.out.println("    --verify-checksum: Verify the checksum (expects SCRIPT#CHECKSUM, outputs 'OK' or 'Error').");
        System.out.println("    --compute-checksum: Compute and append an 8-character checksum (outputs SCRIPT#CHECKSUM).");
        System.out.println("    -: Read expression from stdin.");
        System.out.println("    Examples:");
        System.out.println("      bip380 script-expression --verify-checksum raw(deadbeef)#89f8spxm");
        System.out.println("      bip380 script-expression --compute-checksum pkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8)");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --help                Show this help and exit.");
        System.out.println("  --path {path}         Specify derivation path for derive-key (e.g., /0/1h).");
        System.out.println("  --verify-checksum     Verify checksum for script-expression.");
        System.out.println("  --compute-checksum    Compute checksum for script-expression.");
        System.out.println("  -                     Read input from stdin.");
        System.out.println();
        System.out.println("Notes:");
        System.out.println("  - Spaces and case variations are preserved in script expressions for checksum calculation.");
        System.out.println("  - Errors include 'Error: no checksum', 'Error: Invalid key format', etc.");
    }
}