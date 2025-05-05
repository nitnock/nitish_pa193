package com.naumtinga.command;

import com.naumtinga.command.exception.ScriptExpressionException;
import com.naumtinga.command.util.CommandHelper;
import com.naumtinga.command.util.CommandUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* Processes Bitcoin script expressions: pk, pkh, sh, raw, multi.
   Handles checksum computation/verification. */
public class ScriptExpression {

    // Valid script input charset
    private static final String INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";

    // Checksum charset
    private static final String CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    // Checksum length
    static final int CHECKSUM_LENGTH = 8;

    // Maximum script length
    private static final int MAX_SCRIPT_LENGTH = 10000;

    // Checksum generator values
    private static final long[] GENERATOR = {0xf5dee51989L, 0xa9fdca3312L, 0x1bab10e32dL, 0x3706b1677aL, 0x644d626ffdL};

    // Checksum algorithm constants
    private static final long POLYMOD_MASK = 0x7ffffffffL; // Mask for 35-bit checksum
    private static final int POLYMOD_SHIFT = 35; // Shift for extracting top bits
    private static final int CHECKSUM_SHIFT = 5; // Shift for checksum bit manipulation
    private static final int SYMBOL_GROUP_SIZE = 3; // Number of symbols per group
    private static final int SYMBOL_WEIGHT_1 = 9; // Weight for first symbol in group
    private static final int SYMBOL_WEIGHT_2 = 3; // Weight for second symbol in group
    private static final int BIT_MASK_5 = 31; // Mask for 5-bit values
    private static final int MAX_GROUP_SIZE = 2; // Maximum groups for partial expansion
    private static final int MIN_GROUP_SIZE = 1; // Minimum groups for partial expansion
    private static final int CHECKSUM_XOR = 1; // XOR value for final checksum
    private static final int GROUP_INDEX_SHIFT = 5; // Shift for group index
    private static final int CHECKSUM_INDEX_MAX = 7; // Maximum index for checksum bits

    // Regex for script validation
    private static final Pattern PK_PATTERN = Pattern.compile("^pk\\(\\s*[^\\s]+\\s*\\)$");
    private static final Pattern PKH_PATTERN = Pattern.compile("^pkh\\(\\s*[^\\s]+\\s*\\)$");
    private static final Pattern SH_PK_PATTERN = Pattern.compile("^sh\\(pk\\(\\s*[^\\s]+\\s*\\)\\)$");
    private static final Pattern SH_PKH_PATTERN = Pattern.compile("^sh\\(pkh\\(\\s*[^\\s]+\\s*\\)\\)$");
    private static final Pattern RAW_PATTERN = Pattern.compile("^raw\\(\\s*([0-9A-Fa-f\\s]+)\\s*\\)$");
    private static final Pattern MULTI_PATTERN = Pattern.compile("^multi\\(\\s*(\\d+)\\s*,\\s*((?:\\s*[^\\s]+\\s*,\\s*)*\\s*[^\\s]+\\s*)\\)$");

    /* Executes script expression command with args.
       Supports --verify-checksum, --compute-checksum, -. */
    public static int execute(String[] args) throws ScriptExpressionException {
        if (args == null || args.length == 0) {
            throw new ScriptExpressionException(ScriptExpressionException.ErrorType.INVALID_ARGUMENTS,
                    "Usage: java ScriptExpression [script-expression] [--compute-checksum|--verify-checksum] [-]");
        }

        if (CommandUtils.isHelpRequested(args)) {
            CommandHelper.printScriptExpressionHelp();
            return 0;
        }

        boolean readFromStdin = Arrays.asList(args).contains("-");
        if (readFromStdin) {
            boolean verifyChecksum = Arrays.asList(args).contains("--verify-checksum");
            boolean computeChecksum = Arrays.asList(args).contains("--compute-checksum");
            return executeFromStdin(verifyChecksum, computeChecksum);
        }

        return processCommand(args);
    }

    /* Processes script expression with checksum options. */
    public static String execute(String scriptExpression, boolean verifyChecksum, boolean computeChecksum)
            throws ScriptExpressionException {
        if (scriptExpression == null) {
            throw new ScriptExpressionException(ScriptExpressionException.ErrorType.MISSING_VALUE,
                    "Script expression cannot be null");
        }
        return processExpression(scriptExpression, verifyChecksum, computeChecksum);
    }

    /* Processes stdin script expressions with checksum options. */
    public static int executeFromStdin(boolean verifyChecksum, boolean computeChecksum) throws ScriptExpressionException {
        final int[] exitCode = {0};
        try {
            CommandHelper.readAndProcessStdin("script-expression", input -> {
                String[] stdinArgs = new String[]{input}; // Treat each line as a single script expression
                try {
                    exitCode[0] = processCommand(stdinArgs);
                } catch (ScriptExpressionException e) {
                    throw new RuntimeException(e.getMessage(), e);
                }
            });
        } catch (RuntimeException e) {
            // Wrap IOException from readFromStdin
            throw new ScriptExpressionException(ScriptExpressionException.ErrorType.STDIN_PROCESSING,
                    "Error processing stdin: " + e.getMessage(), e);
        }
        return exitCode[0];
    }

    /* Parses args and processes script expression. */
    private static int processCommand(String[] args) throws ScriptExpressionException {
        boolean verifyChecksum = false;
        boolean computeChecksum = false;
        String scriptExpression = null;

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (arg.equals("script-expression") && i == 0) {
                continue;
            } else if (arg.equals("--verify-checksum")) {
                verifyChecksum = true;
            } else if (arg.equals("--compute-checksum")) {
                computeChecksum = true;
            } else if (arg.equals("-")) {
                continue;
            } else if (scriptExpression == null) {
                scriptExpression = arg;
            }
        }

        if (verifyChecksum && computeChecksum) {
            throw new ScriptExpressionException(ScriptExpressionException.ErrorType.INVALID_ARGUMENTS,
                    "Cannot use both --verify-checksum and --compute-checksum");
        }

        if (scriptExpression == null) {
            throw new ScriptExpressionException(ScriptExpressionException.ErrorType.MISSING_VALUE,
                    "No script expression provided");
        }

        String result = processExpression(scriptExpression, verifyChecksum, computeChecksum);
        System.out.println(result);
        return 0;
    }

    /* Processes script expression with checksum options. */
    private static String processExpression(String scriptExpression, boolean verifyChecksum, boolean computeChecksum)
            throws ScriptExpressionException {
        if (scriptExpression.length() > MAX_SCRIPT_LENGTH) {
            throw new ScriptExpressionException(ScriptExpressionException.ErrorType.SCRIPT_LENGTH,
                    "Script too long, max " + MAX_SCRIPT_LENGTH + " chars");
        }

        String expression = scriptExpression;
        String checksumPart = null;

        if (expression.contains("#")) {
            int hashIndex = expression.lastIndexOf('#');
            checksumPart = expression.substring(hashIndex + 1).toLowerCase(Locale.ENGLISH);
            expression = expression.substring(0, hashIndex);
        }

        if (!isValidScriptExpression(expression)) {
            throw new ScriptExpressionException(ScriptExpressionException.ErrorType.SCRIPT_SYNTAX,
                    "Bad script syntax: " + expression);
        }

        if (!verifyChecksum && !computeChecksum) {
            if (checksumPart != null) {
                if (checksumPart.length() != CHECKSUM_LENGTH) {
                    throw new ScriptExpressionException(ScriptExpressionException.ErrorType.CHECKSUM_VALIDATION,
                            "Checksum must be " + CHECKSUM_LENGTH + " chars");
                }
                String expectedChecksum = computeChecksum(expression);
                if (!expectedChecksum.equals(checksumPart)) {
                    throw new ScriptExpressionException(ScriptExpressionException.ErrorType.CHECKSUM_VALIDATION,
                            "Wrong checksum for: " + scriptExpression);
                }
            }
            return scriptExpression;
        }

        if (computeChecksum) {
            String checksum = computeChecksum(expression);
            return expression + "#" + checksum;
        }

        if (verifyChecksum) {
            if (checksumPart == null || checksumPart.isEmpty()) {
                throw new ScriptExpressionException(ScriptExpressionException.ErrorType.MISSING_CHECKSUM,
                        "No checksum provided");
            }
            if (checksumPart.length() != CHECKSUM_LENGTH) {
                throw new ScriptExpressionException(ScriptExpressionException.ErrorType.CHECKSUM_VALIDATION,
                        "Checksum must be " + CHECKSUM_LENGTH + " chars");
            }
            String expected = computeChecksum(expression);
            if (!expected.equals(checksumPart)) {
                throw new ScriptExpressionException(ScriptExpressionException.ErrorType.CHECKSUM_VALIDATION,
                        "Wrong checksum for: " + scriptExpression);
            }
            return "OK";
        }

        return scriptExpression;
    }

    // Computes checksum for script.
    static String computeChecksum(String script) throws ScriptExpressionException {
        int[] symbols = descsumExpand(script);
        int[] checksum = new int[CHECKSUM_LENGTH];
        int[] combined = Arrays.copyOf(symbols, symbols.length + CHECKSUM_LENGTH);
        long mod = descsumPolymod(combined) ^ CHECKSUM_XOR;

        for (int i = 0; i < CHECKSUM_LENGTH; ++i) {
            checksum[i] = (int) ((mod >> (CHECKSUM_SHIFT * (CHECKSUM_INDEX_MAX - i))) & BIT_MASK_5);
        }

        StringBuilder sb = new StringBuilder(CHECKSUM_LENGTH);
        for (int c : checksum) {
            sb.append(CHECKSUM_CHARSET.charAt(c));
        }

        return sb.toString();
    }

    // Computes polynomial modulo for checksum.
    private static long descsumPolymod(int[] symbols) {
        long chk = CHECKSUM_XOR;
        for (int v : symbols) {
            long top = chk >>> POLYMOD_SHIFT;
            chk = ((chk & POLYMOD_MASK) << CHECKSUM_SHIFT) ^ v;
            for (int i = 0; i < CHECKSUM_SHIFT; i++) {
                if (((top >> i) & CHECKSUM_XOR) != 0) {
                    chk ^= GENERATOR[i];
                }
            }
        }
        return chk;
    }

    // Expands script into symbols for checksum.
    private static int[] descsumExpand(String script) throws ScriptExpressionException {
        List<Integer> symbols = new ArrayList<>();
        List<Integer> groups = new ArrayList<>();

        for (char c : script.toCharArray()) {
            int idx = INPUT_CHARSET.indexOf(c);
            if (idx == -1) {
                throw new ScriptExpressionException(ScriptExpressionException.ErrorType.CHECKSUM_COMPUTATION,
                        "Invalid character in script: " + c);
            }
            symbols.add(idx & BIT_MASK_5);
            groups.add(idx >> GROUP_INDEX_SHIFT);

            if (groups.size() == SYMBOL_GROUP_SIZE) {
                symbols.add(groups.get(0) * SYMBOL_WEIGHT_1 + groups.get(1) * SYMBOL_WEIGHT_2 + groups.get(2));
                groups.clear();
            }
        }

        if (groups.size() == MIN_GROUP_SIZE) {
            symbols.add(groups.get(0));
        } else if (groups.size() == MAX_GROUP_SIZE) {
            symbols.add(groups.get(0) * SYMBOL_WEIGHT_2 + groups.get(1));
        }

        return symbols.stream().mapToInt(Integer::intValue).toArray();
    }

    // Validates script expression syntax.
    static boolean isValidScriptExpression(String expr) {
        String trimmed = expr.trim();

        if (PK_PATTERN.matcher(trimmed).matches() ||
                PKH_PATTERN.matcher(trimmed).matches() ||
                SH_PK_PATTERN.matcher(trimmed).matches() ||
                SH_PKH_PATTERN.matcher(trimmed).matches()) {
            return true;
        }

        Matcher rawMatcher = RAW_PATTERN.matcher(trimmed);
        if (rawMatcher.matches()) {
            String hex = rawMatcher.group(1).replaceAll("\\s+", "");
            return hex.matches("[0-9A-Fa-f]+") && hex.length() % 2 == 0;
        }

        Matcher multiMatcher = MULTI_PATTERN.matcher(trimmed);
        if (multiMatcher.matches()) {
            int k = Integer.parseInt(multiMatcher.group(1));
            String[] keys = multiMatcher.group(2).split("\\s*,\\s*");
            int n = keys.length;
            return k >= 0 && k <= n;
        }

        return false;
    }
}