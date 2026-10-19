# DigSig — Digital Signer Application (open source)

An open-source, cross-platform replacement for the **Digital Signer Application (DigSig)** used with the
Macedonian customs systems:

> Digital Signer Application (DigSig) се користи за авторизација и автентикација на корисниците во СОЦДАД
> и за потпишување на декларации кога се користи CDEPS Trader DP UI.

In English: DigSig authenticates users in СОЦДАД and signs declarations submitted through the CDEPS Trader DP UI,
using the user's qualified certificate, usually on a USB token such as SafeNet / Thales IDPrime. This project is
a drop-in replacement for the official `digsig-signer` Java application (version 1.3.7). It is written in
C#/.NET 10 and runs on Windows, macOS and Linux.

> **Unofficial.** This is an independent reimplementation. It is not affiliated with or endorsed by the Customs
> Administration of the Republic of North Macedonia or by the vendor of the original application.

## Download

Get the latest version from **[Releases](../../releases/latest)**. For Windows, download
`DigSig-x.y.z-win-x64.zip`, unzip it, and run `DigSig.exe`. Nothing else needs to be installed.
Linux and macOS builds are also provided, but they are experimental.

## How it works

The portal in your browser talks to a small HTTPS server on your own computer, just as it did with the
original application:

| Endpoint | Purpose |
|---|---|
| `GET https://localhost:8443/certificate` | Returns the selected certificate as JSON: chain, subject, issuer, VAT number. Used to log in. |
| `POST https://localhost:8443/signature` | Takes an XML document and returns it with an enveloped XML-DSig signature (`201`) |

## Using it

1. Close the original DigSig. Both use port 8443, so only one can run at a time.
2. Start `DigSig` and click the certificate you want to use. The app remembers your choice.
   If you sign for several companies, switch with one click in the window or in the tray icon menu.
3. **First run only:** your browser must trust `https://localhost:8443`. You have three options
   (Settings → *HTTPS certificate*):
   - **Trust in Windows**: adds DigSig's own certificate to your trusted certificates. Windows asks you to confirm.
   - **Import from the original DigSig .jar**: reuses the certificate of `digsig-signer-x.y.z.jar`. Choose this
     if your browser already trusted the original.
   - **Open https://localhost in the browser** and accept the warning once.
4. Optionally press **Test signature** to check the token and PIN.
5. Use the portal as usual. Every request is listed under **Activity**.

Closing the window keeps DigSig running in the tray. Choose **Quit** from the tray menu to stop it.

## Differences from the original

- **No "Select a smart card device" popups.** The original re-opened the private key of every certificate in the
  Windows store on every request. With more than one smart card or token plugged in, Windows then asked which card
  to use. DigSig opens only the selected certificate's key, and only when it signs. It checks whether a token is
  plugged in by quietly asking the inserted cards which keys they hold.
- **Quick company switching.** Each certificate shows its company and VAT number. Your choice is remembered,
  and the tray menu switches between them.
- **The key stays open between signatures**, so the token and Windows can reuse the PIN you already entered.
  **Lock** closes it.
- **The server listens only on this computer.** The original listened on all network interfaces.
- **Optional site allow-list** (Settings → Allowed sites). By default any website may request a signature,
  exactly as before.
- **No Java needed.** DigSig is a single self-contained executable.

## Token access

- **Windows certificate store** (default on Windows): uses the token's Windows driver (SafeNet minidriver).
  Windows shows its own PIN dialog.
- **PKCS#11** (Settings): talks to the token directly through its library: `eTPKCS11.dll` on Windows,
  `libeTPkcs11.so` on Linux, `libeTPkcs11.dylib` on macOS. This is the cross-platform path, and the PIN is asked
  in the app. Install SafeNet Authentication Client for your OS first.
  *Known limitation:* keys that demand the PIN for every signature (`CKA_ALWAYS_AUTHENTICATE`) are reported but
  not supported in this mode yet.
- **.pfx / .p12 files** (Add .pfx…), for software certificates.

## Compatibility

The signature format is the same as the original's: XML-DSig, enveloped, inclusive C14N, RSA-SHA1, SHA-1 digest,
with `X509SubjectName` and `X509Certificate` in `KeyInfo`. The output matches byte for byte, including Java's DN
formatting, attribute order, CRLF line breaks and base64 wrapping. The JSON includes the derived fields the portal
reads (`subjectName`, `issuerString`, `companyVatNumber`), computed with the original's rules for
Makedonski Telekom and KIBS certificates.

This is verified by golden tests. `tests/DigSig.Tests/TestData` holds responses recorded from the original
application (run on Java 8) for fictional test certificates. RSA PKCS#1 v1.5 signatures are deterministic, so
DigSig must reproduce those responses byte for byte. To re-record them with your own copy of the original:

```
tools/capture-golden.sh /path/to/digsig-signer-1.3.7.jar /path/to/java8/bin/java
```

## Command line

```
digsig-cli list                          # certificates and whether their token is plugged in
digsig-cli certificate --cert <id>       # the JSON the portal receives
digsig-cli sign in.xml out.xml --cert <id>
digsig-cli serve --cert <id>             # the server without the UI
digsig-cli import-https-cert <digsig-signer.jar>
```

## Building

Requires the .NET 10 SDK.

```
dotnet test --project tests/DigSig.Tests

dotnet publish src/DigSig.Desktop -c Release -r win-x64 --self-contained \
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -o publish/win-x64
# other platforms: -r osx-arm64, osx-x64, linux-x64
```

## Repository layout

| Path | Contents |
|---|---|
| `src/DigSig.Core` | Signing, Java-compatible formatting, token access, HTTPS server |
| `src/DigSig.Desktop` | Desktop app (Avalonia) |
| `src/DigSig.Cli` | Command-line tool |
| `tests/DigSig.Tests` | Golden and HTTP tests |
| `tools/` | Test certificate generator and golden-file capture script |
