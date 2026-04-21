import json
from typing import Dict
from dataclasses import dataclass, asdict
import datetime

@dataclass
class VerificationArtifactPackage:
    timestamp: str
    env_metadata: Dict[str, str]
    network_trace_summary: str
    stdout_capture: str
    oob_callback_confirmed: bool

class _MockContainerOutput:
    def __init__(self, output: bytes):
        self.output = output

class _MockContainer:
    def exec_run(self, cmd: str) -> _MockContainerOutput:
        if cmd == "whoami": return _MockContainerOutput(b"root\n")
        if cmd.startswith("uname"): return _MockContainerOutput(b"Linux argus-sandbox 6.5.0-35-generic #35~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC x86_64 GNU/Linux\n")
        if cmd.startswith("python"): return _MockContainerOutput(b"Python 3.12.3\n")
        return _MockContainerOutput(b"")
        
    def logs(self) -> bytes:
        return b"INFO: argus-sandbox container initialized...\nINFO: running AddressSanitizer: SEGV (simulated)\n"

class LiveHarness:
    def setup_container(self, target_path: str):
        print(f"[LAYER 4] LiveHarness: Staging Docker container for {target_path}...")
        return _MockContainer()

    def generate_artifact_package(self, container, oob_status: bool) -> VerificationArtifactPackage:
        """Compiles evidence for the disclosure advisory."""
        
        # 1. Capture Environment Metadata (whoami, path, installed pkgs)
        env_data = {
            "user": container.exec_run("whoami").output.decode().strip(),
            "os": container.exec_run("uname -a").output.decode().strip(),
            "python_version": container.exec_run("python --version").output.decode().strip()
        }

        # 2. Capture Network Traces (Simulated: In 2026 we use eBPF for this)
        # We log the egress attempts to the OOB listener
        trace_log = f"OUTBOUND_REQ: POST http://argus-callback.io/ (STATUS: {oob_status})"

        package = VerificationArtifactPackage(
            timestamp=datetime.datetime.utcnow().isoformat(),
            env_metadata=env_data,
            network_trace_summary=trace_log,
            stdout_capture=container.logs().decode()[-500:], # Last 500 chars
            oob_callback_confirmed=oob_status
        )
        
        print("\n" + "="*40)
        print("VERIFICATION ARTIFACT PACKAGE GENERATED")
        print("="*40)
        print(json.dumps(asdict(package), indent=2))
        return package
