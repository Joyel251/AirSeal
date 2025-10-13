"""Demo launcher for AirSeal - Opens both sender and receiver for demonstration."""

import sys
import subprocess
from pathlib import Path

def main():
    """Launch both sender and receiver applications."""
    print("🚀 AirSeal Demo Launcher")
    print("=" * 50)
    print()
    print("Opening both Sender and Receiver applications...")
    print()
    
    src_dir = Path(__file__).parent / "src"
    
    # Launch sender
    sender_path = src_dir / "airseal_sender" / "gui.py"
    print(f"▶️  Starting Sender: {sender_path}")
    sender_process = subprocess.Popen([sys.executable, str(sender_path)])
    
    # Launch receiver
    receiver_path = src_dir / "airseal_receiver" / "gui.py"
    print(f"▶️  Starting Receiver: {receiver_path}")
    receiver_process = subprocess.Popen([sys.executable, str(receiver_path)])
    
    print()
    print("✅ Both applications launched successfully!")
    print()
    print("Demo workflow:")
    print("1. In Sender: Select a file to transfer")
    print("2. In Sender: Click 'Start Scan & Generate Manifest'")
    print("3. In Receiver: Scan the nonce QR (shown in Receiver)")
    print("4. In Sender: Show the manifest QR to Receiver")
    print("5. In Receiver: Scan the manifest QR")
    print("6. Transfer file via USB/CD (or just select the same file for demo)")
    print("7. In Receiver: Click 'Select File to Verify'")
    print("8. Watch the verification and import process!")
    print()
    print("Press Ctrl+C to exit...")
    
    try:
        sender_process.wait()
        receiver_process.wait()
    except KeyboardInterrupt:
        print("\n\n⏹️  Shutting down...")
        sender_process.terminate()
        receiver_process.terminate()
        print("✅ Demo closed.")

if __name__ == "__main__":
    main()
