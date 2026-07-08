import java.io.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class LogAnalyzer {

    // Brute force threshold limits
    private static final int MAX_ATTEMPTS = 3;
    private static Map<String, Integer> failedAttempts = new HashMap<>();
    private static Set<String> whitelist = new HashSet<>();

    // 🕵️‍♂️ Suspicious usernames commonly targeted by hackers (Credential Stuffing)
    private static Set<String> suspiciousUsernames = new HashSet<>(Arrays.asList(
            "admin", "root", "administrator", "guest", "test", "user", "mysql"
    ));

    // 📊 Global counters for our Security Dashboard
    private static int totalLogsProcessed = 0;
    private static int successfulLogins = 0;
    private static int failedLogins = 0;
    private static int criticalAlertsTriggered = 0;

    public static void main(String[] args) {
        // Adding trusted IPs to the whitelist
        whitelist.add("127.0.0.1");
        whitelist.add("192.168.1.1");

        System.out.println("⚡ Cyber-Security Log Analysis Engine Started...");
        System.out.println("------------------------------------------------");

        // Reading the log file from the src folder
        try (BufferedReader br = new BufferedReader(new FileReader("./server.log"))) {
            String logLine;
            while ((logLine = br.readLine()) != null) {
                totalLogsProcessed++;
                analyzeLogLine(logLine);
            }

            // 🔥 Print the beautiful metrics summary when done
            printSecurityDashboard();

        } catch (IOException e) {
            System.err.println("❌ Error reading log file: " + e.getMessage());
        }
    }

    private static void analyzeLogLine(String logLine) {
        // Expected Format: IP | TIMESTAMP | USERNAME | STATUS
        // Example: 192.168.1.50 | 2026-07-08 18:00:01 | admin | FAILED
        String[] parts = logLine.split(" \\| ");
        if (parts.length < 4) return;

        String ip = parts[0].trim();
        String username = parts[2].trim();
        String status = parts[3].trim();

        // 1. Check Whitelist
        if (whitelist.contains(ip)) {
            return;
        }

        // 2. Detect Suspicious Username Attacks (Critical Threat)
        if (suspiciousUsernames.contains(username.toLowerCase()) && status.equalsIgnoreCase("FAILED")) {
            System.out.println("⚠️ CRITICAL WARNING: IP " + ip + " is trying to guess system default username [" + username + "]!");
            criticalAlertsTriggered++;
        }

        // 3. Process Login Status
        if (status.equalsIgnoreCase("SUCCESS")) {
            successfulLogins++;
            failedAttempts.remove(ip); // Reset counter on successful login
        } else if (status.equalsIgnoreCase("FAILED")) {
            failedLogins++;
            failedAttempts.put(ip, failedAttempts.getOrDefault(ip, 0) + 1);

            // Brute Force Detection
            if (failedAttempts.get(ip) >= MAX_ATTEMPTS) {
                System.out.println("🚨 ALERT: Brute Force Attack Detected! Hostile IP: " + ip);
                writeToBlacklist(ip);
            }
        }
    }

    private static void writeToBlacklist(String ipAddress) {
        try (FileWriter fw = new FileWriter("src/blacklist.txt", true);
             PrintWriter pw = new PrintWriter(fw)) {

            DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
            String currentTime = dtf.format(LocalDateTime.now());

            pw.println("[" + currentTime + "] BLOCKED IP: " + ipAddress);
            System.out.println("🔒 SECURITY ACTION: IP " + ipAddress + " has been appended to blacklist.txt");

        } catch (IOException e) {
            System.err.println("❌ Failed writing to blacklist: " + e.getMessage());
        }
    }

    // 📊 CYBER SECURITY ANALYTICS DASHBOARD
    private static void printSecurityDashboard() {
        System.out.println("\n==================================================");
        System.out.println("🛡️        CYBER SECURITY ANALYSIS REPORT         🛡️");
        System.out.println("==================================================");
        System.out.printf("🔹 Total Logs Processed     : %d\n", totalLogsProcessed);
        System.out.printf("✅ Successful Login Attempts: %d\n", successfulLogins);
        System.out.printf("❌ Failed Login Attempts    : %d\n", failedLogins);
        System.out.printf("⚠️ Critical Alerts Triggered : %d\n", criticalAlertsTriggered);
        System.out.println("--------------------------------------------------");

        double safetyScore = totalLogsProcessed > 0 ?
                ((double) (totalLogsProcessed - failedLogins) / totalLogsProcessed) * 100 : 100;

        System.out.printf("📊 System Integrity Score   : %.2f%%\n", safetyScore);
        System.out.println("==================================================");
    }
}
