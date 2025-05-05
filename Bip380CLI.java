package com.naumtinga;

import com.naumtinga.command.DeriveKey;
import com.naumtinga.command.KeyExpression;
import com.naumtinga.command.ScriptExpression;
import com.naumtinga.command.exception.ScriptExpressionException;
import com.naumtinga.command.util.CommandHelper;
import com.naumtinga.command.exception.KeyExpressionException;

import java.util.Arrays;

/**
 * Exception thrown when an invalid argument is provided to the CLI.
 */
class InvalidArgumentException extends Exception {
    public InvalidArgumentException(String message) {
        super(message);
    }
}

/**
 * Exception thrown when a required value is missing in the CLI input.
 */
class MissingValueException extends Exception {
    public MissingValueException(String message) {
        super(message);
    }
}

/**
 * Exception thrown when an unsupported operation is attempted in the CLI.
 */
class UnsupportedOperationException extends Exception {
    public UnsupportedOperationException(String message) {
        super(message);
    }
}

/**
 * Main CLI entry point for BIP-380 commands.
 * Supports subcommands: derive-key, key-expression, and script-expression.
 */
public class Bip380CLI {
    /**
     * Main entry point for the BIP-380 CLI tool.
     * Processes command-line arguments and dispatches to appropriate subcommands.
     *
     * @param args Command-line arguments (e.g., "derive-key <input>", "key-expression <expr>")
     */
    public static void main(String[] args) {
        try {
            // Execute the CLI logic and get the exit code
            int exitCode = execute(args);
            // Exit with the appropriate code (0 for success, 1 for error)
            // In main method:
            int exitC = execute(args);
            System.exit(exitC); // Only here, for CLI launcher; not in deep logic

        } catch (InvalidArgumentException | MissingValueException | UnsupportedOperationException e) {
            // Handle CLI-specific errors
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        } catch (Exception e) {
            // Handle unexpected errors
            System.err.println("Unexpected error: " + e.getMessage());
            System.exit(1);
        }
    }

    /**
     * Executes the CLI logic by dispatching to the appropriate subcommand.
     *
     * @param args Command-line arguments
     * @return Exit code (0 for success, 1 for failure)
     * @throws InvalidArgumentException If an invalid argument is provided
     * @throws MissingValueException If a required value is missing
     * @throws UnsupportedOperationException If an unsupported command is used
     */
    public static int execute(String[] args) throws InvalidArgumentException, MissingValueException, UnsupportedOperationException, ScriptExpressionException {
        // Handle --help and --help <subcommand>
        if (args.length == 0 || "--help".equals(args[0])) {
            // Check if a specific subcommand help is requested
            if (args.length > 1) {
                // Dispatch to the appropriate help message
                switch (args[1]) {
                    case "derive-key":
                        CommandHelper.printDeriveKeyHelp();
                        return 0;
                    case "key-expression":
                        CommandHelper.printKeyExpressionHelp();
                        return 0;
                    case "script-expression":
                        CommandHelper.printScriptExpressionHelp();
                        return 0;
                    default:
                        throw new InvalidArgumentException("Unknown subcommand '" + args[1] + "' for --help.");
                }
            } else {
                // Print general help if no subcommand is specified
                CommandHelper.printGeneralHelp();
                return 0;
            }
        }

        // Extract the command from the arguments
        String command = args[0];
        // Extract sub-arguments (excluding the command name)
        String[] subArgs = Arrays.copyOfRange(args, 1, args.length);

        // Dispatch to the appropriate subcommand
        switch (command) {
            case "derive-key":
                return parseAndExecuteDeriveKey(subArgs);
            case "key-expression":
                return parseAndExecuteKeyExpression(subArgs);
            case "script-expression":
                return parseAndExecuteScriptExpression(subArgs);
            default:
                throw new UnsupportedOperationException("Unknown command: " + command);
        }
    }

    /**
     * Parses and executes the derive-key subcommand.
     *
     * @param args Subcommand arguments
     * @return Exit code (0 for success, 1 for failure)
     * @throws InvalidArgumentException If an invalid argument is provided
     * @throws MissingValueException If a required value is missing
     */
    private static int parseAndExecuteDeriveKey(String[] args) throws InvalidArgumentException, MissingValueException {
        // Check if help is requested
        if (args.length == 0 || (args.length > 0 && "--help".equals(args[0]))) {
            CommandHelper.printDeriveKeyHelp();
            return 0;
        }

        // Initialize variables for derivation path and input
        String derivationPath = "";
        String input = null;
        boolean readFromStdin = false;

        // Parse the subcommand arguments
        for (int i = 0; i < args.length; i++) {
            if ("--path".equals(args[i])) {
                // Check if a value follows the --path option
                if (i + 1 >= args.length) {
                    throw new InvalidArgumentException("Missing value for --path option.");
                }
                // Set the derivation path
                derivationPath = args[i + 1];
                i++;
            } else if ("-".equals(args[i])) {
                // Indicate that input should be read from stdin
                readFromStdin = true;
            } else if (!args[i].startsWith("-") && input == null) {
                // Set the input (seed, xpub, or xprv)
                input = args[i];
            }
        }

        // Handle input from stdin
        if (readFromStdin) {
            // Execute derivation using stdin input
            int exitCode = DeriveKey.executeFromStdin(derivationPath);
            // Check if derivation failed
            if (exitCode != 0) {
                throw new InvalidArgumentException("Failed to process input from stdin.");
            }
            return exitCode;
        }

        // Ensure an input was provided
        if (input == null) {
            throw new MissingValueException("Missing seed/xpriv/xpub input.");
        }

        // Execute derivation with the provided input and path
        int exitCode = DeriveKey.execute(input, derivationPath);
        // Check if derivation failed
        if (exitCode != 0) {
            throw new InvalidArgumentException("Failed to derive key from input.");
        }
        return exitCode;
    }

    /**
     * Parses and executes the key-expression subcommand.
     *
     * @param args Subcommand arguments
     * @return Exit code (0 for success, 1 for failure)
     * @throws InvalidArgumentException If an invalid argument is provided
     */
    private static int parseAndExecuteKeyExpression(String[] args) {
        // Check if help is requested
        if (args.length == 0 || (args.length > 0 && "--help".equals(args[0]))) {
            CommandHelper.printKeyExpressionHelp();
            return 0;
        }

        // Initialize variables for input source
        boolean readFromStdin = false;
        String input = null;

        // Parse subcommand arguments
        for (String arg : args) {
            if ("-".equals(arg)) {
                // Indicate that input should be read from stdin
                readFromStdin = true;
            } else if (!arg.startsWith("-") && input == null) {
                // Set the key expression input
                input = arg;
            }
        }

        try {
            // Handle input from stdin
            if (readFromStdin) {
                // Execute key expression using stdin input
                int exitCode = KeyExpression.executeFromStdin();
                // Print error if execution failed
                if (exitCode != 0) {
                    System.err.println("Error processing key expression from stdin");
                }
                return exitCode;
            }

            // Ensure a key expression was provided
            if (input == null) {
                throw new KeyExpressionException.InvalidArgumentsException("Missing key expression");
            }

            // Execute key expression with provided input
            int exitCode = KeyExpression.execute(input);
            // Print error if execution failed
            if (exitCode != 0) {
                System.err.println("Error processing key expression");
            }
            return exitCode;

        } catch (KeyExpressionException e) {
            // Handle expected key expression errors
            System.err.println("Error in key-expression: " + e.getMessage());
            return 1;
        } catch (Exception e) {
            // Handle unexpected errors
            System.err.println("Unexpected error in key-expression: " + e.getMessage());
            return 1;
        }
    }


    /**
     * Parses and executes the script-expression subcommand.
     *
     * @param args Subcommand arguments
     * @return Exit code (0 for success, 1 for failure)
     * @throws InvalidArgumentException If an invalid argument is provided
     * @throws MissingValueException If a required value is missing
     */
    private static int parseAndExecuteScriptExpression(String[] args) throws InvalidArgumentException, MissingValueException, ScriptExpressionException {
        // Check if help is requested
        if (args.length == 0 || (args.length > 0 && "--help".equals(args[0]))) {
            CommandHelper.printScriptExpressionHelp();
            return 0;
        }

        // Initialize variables for script expression options
        boolean readFromStdin = false;
        boolean verifyChecksum = false;
        boolean computeChecksum = false;
        String scriptExpression = null;

        // Parse the subcommand arguments
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if ("--verify-checksum".equals(arg)) {
                // Enable checksum verification
                verifyChecksum = true;
            } else if ("--compute-checksum".equals(arg)) {
                // Enable checksum computation
                computeChecksum = true;
            } else if ("-".equals(arg)) {
                // Indicate that input should be read from stdin
                readFromStdin = true;
            } else if (!arg.startsWith("-") && scriptExpression == null) {
                // Set the script expression input
                scriptExpression = arg;
            }
        }

        // Check for conflicting options
        if (verifyChecksum && computeChecksum) {
            throw new InvalidArgumentException("Use only '--verify-checksum' or '--compute-checksum', not both.");
        }

        // Handle input from stdin
        if (readFromStdin) {
            // Execute script expression using stdin input
            ScriptExpression.executeFromStdin(verifyChecksum, computeChecksum);
            return 0;
        }

        // Ensure a script expression was provided
        if (scriptExpression == null) {
            throw new MissingValueException("No script expression provided.");
        }

        // Execute script expression with the provided input and options
        ScriptExpression.execute(scriptExpression, verifyChecksum, computeChecksum);
        return 0;
    }
}
