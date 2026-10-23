MH Security Tool Installer — modified build

Features
- System dependencies are shown individually under the expandable "System dependencies" row.
- Components found before installation are labelled "Already installed".
- Missing components are shown as "Not installed"; items still missing after final verification show "Missing".
- The final-check column shows "OK" only if the corresponding verification passed.
- The Version column shows APT package versions, tool version output, or an explicit unknown/not-installed label.
- Select any table row to see longer details (package name, purpose, binary path, verification command, and output).
- Sequential install steps, live log, progress, and a text report are retained.

Run on Kali/Debian Linux
1. Extract the ZIP.
2. Open a terminal inside the extracted mh_tool_installer directory.
3. Run:
   chmod +x run_mh_installer.sh
   ./run_mh_installer.sh

The launcher requests sudo permission for APT packages. Do not run the Python GUI with sudo.
Report path: ~/.local/share/mh-tool-installer/install_report.txt

Scope note: this installer downloads and verifies tools; it does not run scans.
Use security tools only on systems you own or are explicitly authorized to test.
