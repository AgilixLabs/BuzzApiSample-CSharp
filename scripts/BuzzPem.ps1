<#
.SYNOPSIS
    Shared RSA key-generation and PEM-export helpers for the Buzz OAuth scripts.

.DESCRIPTION
    Dot-source this file to get RSA key generation and PEM export that work
    identically on Windows PowerShell 5.1 (.NET Framework 4.x) and PowerShell 7+
    (.NET 5+), with no external tools:

        . "$PSScriptRoot\BuzzPem.ps1"

    Windows PowerShell 5.1 is the shell that ships with Windows 11, and .NET
    Framework 4.x has none of the PEM APIs added in .NET 5
    (ExportRSAPrivateKeyPem / ExportSubjectPublicKeyInfoPem / ImportFromPem).
    Rather than shelling out to OpenSSL — which is not part of Windows and would
    make this sample require a separate install — these helpers write the ASN.1
    DER structures directly from RSAParameters, which .NET Framework does expose.

    Exported functions:
      New-BuzzRsaKey        Generate an RSA key of a given size.
      Export-BuzzSpkiPem    Public key  -> SubjectPublicKeyInfo PEM ("BEGIN PUBLIC KEY").
      Export-BuzzPkcs1Pem   Private key -> PKCS#1 RSAPrivateKey PEM ("BEGIN RSA PRIVATE KEY").

.NOTES
    The PEM produced here is byte-identical to what OpenSSL and .NET 5+ produce
    for the same key, and is accepted by RSA.ImportFromPem() in the sample app.
#>

# ── ASN.1 DER primitives ──────────────────────────────────────────────────────

function ConvertTo-BuzzDerLength([int] $Length) {
    # DER definite-length: short form below 0x80, otherwise 0x8n followed by n big-endian bytes.
    if ($Length -lt 0x80) { return [byte[]] @($Length) }

    $bytes = New-Object System.Collections.Generic.List[byte]
    $v = $Length
    while ($v -gt 0) {
        $bytes.Insert(0, [byte]($v -band 0xFF))
        $v = $v -shr 8
    }
    return [byte[]] (@([byte](0x80 -bor $bytes.Count)) + $bytes.ToArray())
}

function ConvertTo-BuzzDerTlv([byte] $Tag, [byte[]] $Value) {
    return [byte[]] (@($Tag) + (ConvertTo-BuzzDerLength $Value.Length) + $Value)
}

function ConvertTo-BuzzDerInteger([byte[]] $Bytes) {
    # RSAParameters values are unsigned big-endian; DER INTEGER is signed two's complement.
    # Strip redundant leading zero bytes, keeping at least one byte.
    $i = 0
    while ($i -lt ($Bytes.Length - 1) -and $Bytes[$i] -eq 0x00) { $i++ }
    $trimmed = [byte[]] $Bytes[$i..($Bytes.Length - 1)]

    # A set high bit would read as negative, so prefix a zero byte to keep it positive.
    if ($trimmed[0] -band 0x80) { $trimmed = [byte[]] (@([byte]0x00) + $trimmed) }

    return ConvertTo-BuzzDerTlv 0x02 $trimmed
}

function ConvertTo-BuzzPem([byte[]] $Der, [string] $Label) {
    $b64 = [Convert]::ToBase64String($Der)
    $sb  = New-Object System.Text.StringBuilder
    [void] $sb.Append("-----BEGIN $Label-----`n")
    for ($i = 0; $i -lt $b64.Length; $i += 64) {
        [void] $sb.Append($b64.Substring($i, [Math]::Min(64, $b64.Length - $i))).Append("`n")
    }
    [void] $sb.Append("-----END $Label-----`n")
    return $sb.ToString()
}

# ── Key generation ────────────────────────────────────────────────────────────

function New-BuzzRsaKey {
    <#
    .SYNOPSIS
        Generates an RSA key of the requested size.
    .DESCRIPTION
        Always pass the size to RSA.Create().  The parameterless
        RSA.Create() returns a 1024-bit RSACryptoServiceProvider on
        .NET Framework — below the 2048-bit minimum Buzz accepts — and its
        KeySize property is read-only there, so it cannot be corrected after
        the fact.  RSA.Create(int) honours the size on both runtimes.
    #>
    param(
        [ValidateRange(2048, 16384)]
        [int] $KeySize = 2048
    )
    return [System.Security.Cryptography.RSA]::Create($KeySize)
}

# ── PEM export ────────────────────────────────────────────────────────────────

function Export-BuzzSpkiPem {
    <#
    .SYNOPSIS
        Exports the public half of an RSA key as a SubjectPublicKeyInfo PEM.
    .DESCRIPTION
        This is the format Buzz expects when registering an OAuth public key.
        Equivalent to .NET 5+ ExportSubjectPublicKeyInfoPem() and to
        `openssl pkey -pubout`.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.RSA] $Rsa
    )

    $p = $Rsa.ExportParameters($false)

    # RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    $rsaPublicKey = ConvertTo-BuzzDerTlv 0x30 (
        (ConvertTo-BuzzDerInteger $p.Modulus) + (ConvertTo-BuzzDerInteger $p.Exponent))

    # BIT STRING wrapping: leading 0x00 = zero unused bits.
    $bitString = ConvertTo-BuzzDerTlv 0x03 ([byte[]] (@([byte]0x00) + $rsaPublicKey))

    # AlgorithmIdentifier ::= SEQUENCE { OID 1.2.840.113549.1.1.1 (rsaEncryption), NULL }
    $algorithmId = [byte[]] @(0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
                              0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00)

    # SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
    $spki = ConvertTo-BuzzDerTlv 0x30 ($algorithmId + $bitString)

    return ConvertTo-BuzzPem $spki 'PUBLIC KEY'
}

function Export-BuzzPkcs1Pem {
    <#
    .SYNOPSIS
        Exports an RSA private key as a PKCS#1 RSAPrivateKey PEM.
    .DESCRIPTION
        Equivalent to .NET 5+ ExportRSAPrivateKeyPem().  RSA.ImportFromPem()
        in the sample app accepts this format.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.RSA] $Rsa
    )

    $p = $Rsa.ExportParameters($true)

    # RSAPrivateKey ::= SEQUENCE {
    #   version INTEGER (0), modulus, publicExponent, privateExponent,
    #   prime1, prime2, exponent1, exponent2, coefficient }
    $body = [byte[]] @(0x02, 0x01, 0x00)                     # version 0
    foreach ($value in @($p.Modulus, $p.Exponent, $p.D,
                         $p.P, $p.Q, $p.DP, $p.DQ, $p.InverseQ)) {
        $body += ConvertTo-BuzzDerInteger $value
    }

    return ConvertTo-BuzzPem (ConvertTo-BuzzDerTlv 0x30 $body) 'RSA PRIVATE KEY'
}
