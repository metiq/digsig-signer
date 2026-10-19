An unofficial, open-source replacement for the **Digital Signer Application (DigSig)**, used to log in to СОЦДАД and sign declarations in CDEPS Trader DP UI. No Java required.

## Download

| System | File |
|---|---|
| **Windows 10/11 (64-bit)** | `DigSig-…-win-x64.zip` |
| Linux (64-bit), experimental | `DigSig-…-linux-x64.tar.gz` |
| macOS Apple silicon, experimental | `DigSig-…-osx-arm64.tar.gz` |
| macOS Intel, experimental | `DigSig-…-osx-x64.tar.gz` |

`SHA256SUMS.txt` lists the checksums of all files.

## Install on Windows

1. Close the original DigSig (Java) if it is running. Both use port 8443.
2. Unzip, then run `DigSig.exe`.
   The program is not code-signed yet, so Windows SmartScreen may say *"Windows protected your PC"*.
   Click **More info → Run anyway**.
3. Click the certificate you want to sign with.
4. First run only, in Settings → *HTTPS certificate*, either
   **Import from the original DigSig .jar** (if your browser already trusted the original) or **Trust in Windows**.
5. Optionally press **Test signature**, then use the portal as usual.

On macOS and Linux, install SafeNet Authentication Client and enable PKCS#11 in Settings. On macOS you may need
`xattr -d com.apple.quarantine DigSig/DigSig` before the first start.

`digsig-cli` in the same folder is a command-line tool for diagnostics (`digsig-cli list`).

