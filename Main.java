package com.pv286.bip380;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;



public class Main {
    public static void main(String[] args) {
        for (String arg : args) {
            if (arg.equals("--help")) {
                HelpCommand.display();
                System.exit(0);
            }
        }

        if (args.length == 0) {
            System.err.println("Error: No sub-command provided");
            System.exit(1);
        }

        String subCommand = args[0];
        String[] subArgs = new String[args.length - 1];
        System.arraycopy(args, 1, subArgs, 0, subArgs.length);

        String value = null;
        String path = null;
        boolean useStdin = false;
        boolean verifyChecksum = false;
        boolean computeChecksum = false;

        for (int i = 0; i < subArgs.length; i++) {
            if (subArgs[i].equals("-")) {
                useStdin = true;
            } else if (subArgs[i].equals("--path") && i + 1 < subArgs.length) {
                path = subArgs[i + 1];
                i++; // Skip the next arg
            } else if (subArgs[i].equals("--verify-checksum")) {
                verifyChecksum = true;
            } else if (subArgs[i].equals("--compute-checksum")) {
                computeChecksum = true;
            } else if (!subArgs[i].startsWith("-") && value == null && !useStdin) {
                value = subArgs[i];
            } else if (!subArgs[i].equals("--path") && subArgs[i].startsWith("-") && !subArgs[i].equals("-")) {
                System.err.println("Error: Invalid argument");
                System.exit(1);
            }
        }

        final boolean finalVerifyChecksum = verifyChecksum;
        final boolean finalComputeChecksum = computeChecksum;

        int exitCode = 0;
        switch (subCommand) {
            case "derive-key":
                if (useStdin) {
                    exitCode = processStdinBatch("derive-key", subArgs, DeriveKeyCommand::derive);
                } else if (value != null) {
                    try {
                        String[] deriveArgs = path != null ? new String[]{value, "--path", path} : new String[]{value};
                        DeriveKeyCommand.derive(deriveArgs);
                    } catch (Exception e) {
                        System.err.println("Error: " + e.getMessage());
                        exitCode = 1;
                    }
                } else {
                    System.err.println("Error: Missing {value} or '-'");
                    System.exit(1);
                }
                break;
            case "key-expression":
                if (useStdin) {
                    exitCode = processStdin("key-expression", subArgs, KeyExpressionCommand::parseAndEcho);
                } else if (value != null) {
                    try {
                        KeyExpressionCommand.parseAndEcho(new String[]{value});
                    } catch (Exception e) {
                        System.err.println("Error: " + e.getMessage());
                        exitCode = 1;
                    }
                } else {
                    System.err.println("Error: Missing {expr} or '-'");
                    System.exit(1);
                }
                break;
            case "script-expression":
                if (finalVerifyChecksum && finalComputeChecksum) {
                    System.err.println("Error: use only '--verify-checksum' or '--compute-checksum', not both");
                    System.exit(1);
                }
                if (useStdin) {
                    exitCode = processStdin("script-expression", subArgs, 
                        args1 -> ScriptExpressionCommand.process(args1, finalVerifyChecksum, finalComputeChecksum));
                } else if (value != null) {
                    try {
                        ScriptExpressionCommand.process(new String[]{value}, finalVerifyChecksum, finalComputeChecksum);
                    } catch (Exception e) {
                        System.err.println("Error: " + e.getMessage());
                        exitCode = 1;
                    }
                } else {
                    System.err.println("Error: Missing {expr} or '-'");
                    System.exit(1);
                }
                break;
            default:
                System.err.println("Error: Unknown sub-command: " + subCommand);
                System.exit(1);
        }
        System.exit(exitCode);
    }

    public static int processStdin(String subCommand, String[] args, RunnableWithArgs processor) {
        boolean hasDash = false;
        String path = null;
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("-")) {
                hasDash = true;
            } else if (args[i].equals("--path") && i + 1 < args.length) {
                path = args[i + 1];
                i++;
            } else if (subCommand.equals("derive-key") && !args[i].equals("--path") && !args[i].startsWith("-")) {
                continue;
            } else if (subCommand.equals("script-expression") && !args[i].equals("--verify-checksum") && !args[i].equals("--compute-checksum") && !args[i].startsWith("-")) {
                continue;
            } else if (!args[i].equals("--path") && !args[i].equals("--verify-checksum") && !args[i].equals("--compute-checksum") && args[i].startsWith("-") && !args[i].equals("-")) {
                System.err.println("Error: Invalid argument with '-'");
                return 1;
            }
        }
        if (!hasDash) {
            System.err.println("Error: '-' required for stdin");
            return 1;
        }
        int exitCode = 0;
        try (Scanner scanner = new Scanner(System.in, "UTF-8")) {
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine().replace("\r", "").trim();
                if (!line.isEmpty()) {
                    try {
                        String[] processArgs = path != null ? new String[]{line, "--path", path} : new String[]{line};
                        processor.run(processArgs);
                    } catch (Exception e) {
                        System.err.println("Error: " + e.getMessage());
                        exitCode = 1;
                    }
                }
            }
        }
        return exitCode;
    }

    public static int processStdinBatch(String subCommand, String[] args, RunnableWithArgs processor) {
        boolean hasDash = false;
        String path = null;
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("-")) {
                hasDash = true;
            } else if (args[i].equals("--path") && i + 1 < args.length) {
                path = args[i + 1];
                i++;
            } else if (!args[i].equals("--path") && subCommand.equals("derive-key") && !args[i].startsWith("-")) {
                continue;
            } else if (!args[i].equals("--path") && args[i].startsWith("-")) {
                System.err.println("Error: Invalid argument with '-'");
                return 1;
            }
        }
        if (!hasDash) {
            System.err.println("Error: '-' required for stdin");
            return 1;
        }
        List<String> lines = new ArrayList<>();
        try (Scanner scanner = new Scanner(System.in, "UTF-8")) {
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine().replace("\r", "").trim();
                if (!line.isEmpty()) {
                    lines.add(line);
                }
            }
        }
        int exitCode = 0;
        for (String line : lines) {
            String[] processArgs = path != null ? new String[]{line, "--path", path} : new String[]{line};
            try {
                processor.run(processArgs);
            } catch (Exception e) {
                System.err.println("Error: " + e.getMessage());
                exitCode = 1;
            }
        }
        return exitCode;
    }

    private static String getPath(String[] args) {
        for (int i = 0; i < args.length - 1; i++) {
            if (args[i].equals("--path")) {
                return args[i + 1];
            }
        }
        return null;
    }

    @FunctionalInterface
    interface RunnableWithArgs {
        void run(String[] args);
    }
}

//to sign commit