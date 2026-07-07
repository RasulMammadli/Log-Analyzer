import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;

/**
 * LogAnalyzer - A tool to detect potential Brute Force attacks from server logs.
 * Author: Rasul Mammadli
 */
public class LogAnalyzer {
    // Threshold for triggering a security alert
    private static final int MAX_ATTEMPTS = 5;

    public static void main(String[] args) {
        String logFilePath = "server.log";
        HashMap<String, Integer> failedAttempts = new HashMap<>();

        try (BufferedReader br = new BufferedReader(new FileReader(logFilePath))) {
            String line;
            System.out.println("🔍 Starting log analysis...");

            while ((line = br.readLine()) != null) {
                // Check if the log line indicates a failed login attempt
                if (line.contains("LOGIN_FAILED")) {
                    String ipAddress = extractIP(line);

                    // Increment the failed attempt counter for this IP address
                    failedAttempts.put(ipAddress, failedAttempts.getOrDefault(ipAddress, 0) + 1);

                    // Trigger an alert if the threshold is reached
                    if (failedAttempts.get(ipAddress) >= MAX_ATTEMPTS) {
                        System.out.println("🚨 ALERT: Potential Brute Force Attack Detected! IP: " + ipAddress);
                        writeToBlacklist(ipAddress);
                    }
                }
            }
            System.out.println("✅ Analysis completed successfully.");

        } catch (IOException e) {
            System.out.println("❌ Error reading the log file: " + e.getMessage());
        }
    }

    /**
     * Helper method to extract the IP address from the end of the log line.
     */
    private static String extractIP(String logLine) {
        String[] parts = logLine.split(" ");
        return parts[parts.length - 1];
    }
    private static void writeToBlacklist(String ipAddress) {
        try (java.io.FileWriter fw = new java.io.FileWriter("blacklist.txt", true);
             java.io.PrintWriter pw = new java.io.PrintWriter(fw)) {

            pw.println(ipAddress);
            System.out.println("🔒 SECURITY ACTION: IP " + ipAddress + " has been written to blacklist.txt");

        } catch (java.io.IOException e) {
            System.err.println("❌ Error writing to blacklist file: " + e.getMessage());
        }
    }
}
