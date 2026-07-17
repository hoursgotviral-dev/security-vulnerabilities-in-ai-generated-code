import subprocess
import datetime
import os

OUTPUT_FILE = "../tools_versions.txt"

tools = [
    ["python", "--version"],
    ["clang", "--version"],
    ["gcc", "--version"],
    ["semgrep", "--version"],
    ["bandit", "--version"],
    ["eslint", "--version"],
    ["flawfinder", "--version"],
    ["cbmc", "--version"],
    ["klee", "--version"],
    ["afl-clang-fast", "--version"],
    ["codeql", "--version"]
]

def log_versions():
    with open(OUTPUT_FILE, "w") as f:
        f.write(f"Toolchain Version Log - {datetime.datetime.now()}\n")
        f.write("-" * 40 + "\n")
        
        for cmd in tools:
            tool_name = cmd[0]
            f.write(f"Checking: {tool_name}\n")
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    output = result.stdout.strip() or result.stderr.strip()
                    f.write(f"{output}\n")
                else:
                    f.write(f"ERROR: Tool installed but returned error.\n")
            except FileNotFoundError:
                f.write(f"MISSING: {tool_name} is not installed or not in PATH.\n")
            
            f.write("-" * 40 + "\n")
            
    print(f"Successfully generated {OUTPUT_FILE}")

if __name__ == "__main__":
    log_versions()