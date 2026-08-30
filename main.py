import collections
import time

class AuditableSecurityMonitor:
    """
    A small, auditable security monitor that detects anomalies in login attempts.
    It provides clear explanations for why an event is flagged as anomalous.
    """
    def __init__(self, failed_login_threshold=3, time_window_seconds=60):
        # Configuration for what constitutes an anomaly
        self.failed_login_threshold = failed_login_threshold
        self.time_window_seconds = time_window_seconds
        # Store login attempts: {ip: [(timestamp, success_status), ...]}
        self.login_attempts = collections.defaultdict(list)
        # Store known suspicious IPs (for demonstration of a simple rule)
        self.suspicious_ips = {"192.168.1.100", "10.0.0.5"} # Example "blacklist"

    def _clean_old_attempts(self, ip):
        """Removes attempts outside the time window for a given IP."""
        current_time = time.time()
        self.login_attempts[ip] = [
            (ts, status) for ts, status in self.login_attempts[ip]
            if current_time - ts <= self.time_window_seconds
        ]

    def process_login_event(self, ip_address, success):
        """Processes a login event and checks for anomalies, providing explanations."""
        current_time = time.time()
        self.login_attempts[ip_address].append((current_time, success))
        self._clean_old_attempts(ip_address) # Keep data fresh within the window

        anomalies = []

        # Rule 1: High rate of failed login attempts from a single IP
        failed_attempts_count = sum(1 for ts, s in self.login_attempts[ip_address] if not s)
        if failed_attempts_count >= self.failed_login_threshold:
            # This is the "auditable" part: explain *why* it's an anomaly
            anomalies.append(
                f"Anomaly Detected: IP {ip_address} has {failed_attempts_count} failed login attempts "
                f"within the last {self.time_window_seconds} seconds. (Threshold: {self.failed_login_threshold})"
            )

        # Rule 2: Login attempt from a known suspicious IP
        if ip_address in self.suspicious_ips:
            # Another auditable explanation for the detection
            anomalies.append(
                f"Anomaly Detected: IP {ip_address} is on the known suspicious IP list."
            )

        if anomalies:
            print(f"ALERT for IP {ip_address}:")
            for anomaly_msg in anomalies:
                print(f"  - {anomaly_msg}") # Display the clear reason for the alert
            return True
        else:
            print(f"IP {ip_address}: Normal activity.")
            return False

# --- Example Usage ---
if __name__ == "__main__":
    # Initialize the monitor with a short time window for quick demonstration
    monitor = AuditableSecurityMonitor(failed_login_threshold=3, time_window_seconds=30)

    print("--- Simulating Login Events ---")

    # Normal activity
    monitor.process_login_event("192.168.1.1", True)
    monitor.process_login_event("192.168.1.2", True)
    monitor.process_login_event("192.168.1.1", False) # One failed attempt
    monitor.process_login_event("192.168.1.3", True)

    time.sleep(1) # Simulate time passing

    # Trigger Rule 1: Multiple failed attempts from one IP (simulating brute-force)
    print("\n--- Scenario: Brute-force attempt ---")
    monitor.process_login_event("192.168.1.50", False)
    monitor.process_login_event("192.168.1.50", False)
    monitor.process_login_event("192.168.1.50", False) # This should trigger an anomaly
    monitor.process_login_event("192.168.1.50", True) # Even if it succeeds, the failed attempts count is high

    time.sleep(1)

    # Trigger Rule 2: Login from known suspicious IP
    print("\n--- Scenario: Login from known suspicious IP ---")
    monitor.process_login_event("192.168.1.100", False) # This IP is in suspicious_ips
    monitor.process_login_event("10.0.0.5", True) # Another suspicious IP

    time.sleep(35) # Wait for time window to expire for 192.168.1.50

    print("\n--- Scenario: Old attempts cleared, new attempts are normal ---")
    monitor.process_login_event("192.168.1.50", False) # Should not trigger Rule 1 now, as old attempts are gone
    monitor.process_login_event("192.168.1.50", True)
