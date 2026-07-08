import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.HashSet;

public class LogAnalyzer {

    private static final int MAX_ATTEMPTS = 3;

    public static void main(String[] args) {
        HashMap<String, Integer> failedAttempts = new HashMap<>();

        // 1. Create a Whitelist for trusted IPs
        HashSet<String> whitelist = new HashSet<>();
        whitelist.add("127.0.0.1"); // Localhost
        whitelist.add("192.168.1.1"); // Trustworthy Gateway

        System.out.println("🔍 Starting log analysis...");

        // Reading the log file (Using your file-reading structure)
        try (BufferedReader br = new BufferedReader(new FileReader("server.log"))) {
            String logLine;

            while ((logLine = br.readLine()) != null) {
                // Extract IP from the log line
                String ipAddress = extractIP(logLine);

                // 2. Whitelist Check: If IP is safe, skip completely
                if (whitelist.contains(ipAddress)) {
                    System.out.println("🛡️ WHITELIST ACTIVE: Trusted IP skipped -> " + ipAddress);
                    continue;
                }

                // Track failed login attempts
                if (logLine.contains("FAILED") || logLine.contains("Failed")) {
                    failedAttempts.put(ipAddress, failedAttempts.getOrDefault(ipAddress, 0) + 1);

                    // Trigger alert if threshold is reached
                    if (failedAttempts.get(ipAddress) >= MAX_ATTEMPTS) {
                        System.out.println("🚨 ALERT: Potential Brute Force Attack Detected from " + ipAddress);
                        writeToBlacklist(ipAddress);
                    }
                }
            }

            System.out.println("✅ Analysis completed successfully.");

        } catch (IOException e) {
            System.out.println("❌ Error reading the log file: " + e.getMessage());
        }
    }

    // Helper method to extract the IP address from the end of the log line
    private static String extractIP(String logLine) {
        String[] parts = logLine.split(" ");
        return parts[parts.length - 1];
    }

    // Updated with Timestamping feature
    private static void writeToBlacklist(String ipAddress) {
        try (java.io.FileWriter fw = new java.io.FileWriter("blacklist.txt", true);
             java.io.PrintWriter pw = new java.io.PrintWriter(fw)) {

            // Generate professional timestamp
            DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
            String currentTime = dtf.format(LocalDateTime.now());

            // Write timestamped block log to file
            pw.println("[" + currentTime + "] BLOCKED IP: " + ipAddress);
            System.out.println("🔒 SECURITY ACTION: IP " + ipAddress + " has been logged to blacklist.txt");

        } catch (java.io.IOException e) {
            System.err.println("❌ Error writing to blacklist file: " + e.getMessage());
        }
    }
}
