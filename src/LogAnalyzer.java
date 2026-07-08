import java.io.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class LogAnalyzer {

    // Brute force threshold limits
    private static final int MAX_ATTEMPTS = 3;
    private static Map<String, Integer> failedAttempts = new HashMap<>();
    private static Set<String> whitelist = new HashSet<>();

    // Global counters for our Security Dashboard
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

        // Reading the log file
        try (BufferedReader br = new BufferedReader(new FileReader("./server.log"))) {
            String logLine;
            while ((logLine = br.readLine()) != null) {
                totalLogsProcessed++;
                analyzeLogLine(logLine);
            }

            // Print the beautiful metrics summary when done
            printSecurityDashboard();

        } catch (IOException e) {
            System.err.println("❌ Error reading log file: " + e.getMessage());
        }
    }

    private static void analyzeLogLine(String logLine) {
        if (logLine == null || logLine.trim().isEmpty()) return;

        // 1. Uğursuz giriş cəhdlərinin analizi (LOGIN_FAILED)
        if (logLine.contains("LOGIN_FAILED")) {
            failedLogins++;

            // Sətrin ən sonundakı İP ünvanını tapırıq
            String[] words = logLine.split(" ");
            String ip = words[words.length - 1].trim();

            // Whitelist yoxlanışı
            if (whitelist.contains(ip)) return;

            failedAttempts.put(ip, failedAttempts.getOrDefault(ip, 0) + 1);

            // İstifadəçi adı olaraq admin/root yoxlanışı
            if (logLine.toLowerCase().contains("admin") || logLine.toLowerCase().contains("root")) {
                criticalAlertsTriggered++;
                System.out.println("⚠️ CRITICAL ALERT: Malicious credential attempt from IP: " + ip);
            }

            // Brute Force Təyini (3 və ya daha çox uğursuz cəhd)
            if (failedAttempts.get(ip) >= MAX_ATTEMPTS) {
                criticalAlertsTriggered++;
                System.out.println("🚨 ALERT: Brute Force Attack Detected! Hostile IP: " + ip);
                writeToBlacklist(ip);
            }
        }
        // 2. Uğurlu girişlərin analizi
        else if (logLine.contains("logged in successfully")) {
            successfulLogins++;

            String[] words = logLine.split(" ");
            String ip = words[words.length - 1].trim();

            failedAttempts.remove(ip); // Uğurlu giriş olduqda sıfırla
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
