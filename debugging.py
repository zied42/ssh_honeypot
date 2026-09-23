#!/usr/bin/env python3
"""Test logging system"""

import sys
import os

print("=" * 60)
print("LOGGING DIAGNOSTIC")
print("=" * 60)

# Test 1: Check if logs directory exists
print("\n1. Checking logs directory...")
if os.path.exists("logs"):
    print("  ✓ logs/ directory exists")
else:
    print("  ✗ logs/ directory does NOT exist")
    print("  Creating logs/ directory...")
    os.makedirs("logs")
    print("  ✓ logs/ directory created")

# Test 2: Check write permissions
print("\n2. Checking write permissions...")
try:
    test_file = "logs/test_write.txt"
    with open(test_file, "w") as f:
        f.write("test")
    os.remove(test_file)
    print("  ✓ Can write to logs/ directory")
except Exception as e:
    print(f"  ✗ Cannot write to logs/: {e}")

# Test 3: Import logger module
print("\n3. Testing logger import...")
try:
    from logs.logger import funnel_logger, cmd_logger, alert_logger

    print("  ✓ Logger module imported successfully")
except Exception as e:
    print(f"  ✗ Failed to import logger: {e}")
    import traceback

    traceback.print_exc()
    sys.exit(1)

# Test 4: Test actual logging
print("\n4. Testing logger functionality...")

try:
    funnel_logger.info("TEST: Funnel logger test message")
    print("  ✓ funnel_logger.info() executed")
except Exception as e:
    print(f"  ✗ funnel_logger failed: {e}")

try:
    cmd_logger.info("TEST: Command logger test message")
    print("  ✓ cmd_logger.info() executed")
except Exception as e:
    print(f"  ✗ cmd_logger failed: {e}")

try:
    alert_logger.warning("TEST: Alert logger test message")
    print("  ✓ alert_logger.warning() executed")
except Exception as e:
    print(f"  ✗ alert_logger failed: {e}")

# Test 5: Check if log files were created
print("\n5. Checking log files...")

expected_logs = ["audits.log", "cmd_audits.log", "alerts.log"]

for log_file in expected_logs:
    log_path = os.path.join("logs", log_file)
    if os.path.exists(log_path):
        size = os.path.getsize(log_path)
        print(f"  ✓ {log_file} exists ({size} bytes)")

        # Read last line
        try:
            with open(log_path, "r") as f:
                lines = f.readlines()
                if lines:
                    print(f"    Last line: {lines[-1].strip()}")
        except:
            pass
    else:
        print(f"  ✗ {log_file} does NOT exist")

# Test 6: Check LOG_DIR configuration
print("\n6. Checking configuration...")
try:
    from config.settings import LOG_DIR

    print(f"  LOG_DIR = '{LOG_DIR}'")
    if LOG_DIR and not os.path.exists(LOG_DIR):
        print(f"  ⚠️  LOG_DIR '{LOG_DIR}' does not exist!")
        print(f"  Creating {LOG_DIR}...")
        os.makedirs(LOG_DIR)
except ImportError:
    print("  ⚠️  Could not import LOG_DIR from config.settings")

print("\n" + "=" * 60)
print("DIAGNOSTIC COMPLETE")
print("=" * 60)

# Final check
print("\n7. Final verification...")
all_exist = all(os.path.exists(f"logs/{log}") for log in expected_logs)
if all_exist:
    print("  ✅ ALL SYSTEMS GO - Logging is working!")
else:
    print("  ❌ LOGGING NOT WORKING - Check errors above")