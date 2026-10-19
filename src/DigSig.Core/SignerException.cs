namespace DigSig.Core;

/// <summary>An error with a message meant for the user (token missing, wrong PIN, ...).</summary>
public class SignerException(string message, Exception? inner = null) : Exception(message, inner);
