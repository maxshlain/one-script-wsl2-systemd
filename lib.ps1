$powershellProcess = (Get-Process -Id $PID).ProcessName + '.exe'

if (-not [System.Environment]::Is64BitProcess) {
    # Allow launching WSL from 32 bit powershell
    $wslPath = "$env:windir\sysnative\wsl.exe"
} else {
    $wslPath = "$env:windir\system32\wsl.exe"
}

function Get-IniContent($filePath)
{
    $ini = @{}
    switch -regex -file $FilePath
    {
        "^\[(.+)\]" # Section
        {
            $section = $matches[1]
            $ini[$section] = @{}
            $CommentCount = 0
        }
        "^(;.*)$" # Comment
        {
            $value = $matches[1]
            $CommentCount = $CommentCount + 1
            $name = "Comment" + $CommentCount
            $ini[$section][$name] = $value
        }
        "(.+?)\s*=(.*)" # Key
        {
            $name,$value = $matches[1..2]
            $ini[$section][$name] = $value
        }
    }
    return $ini
}

function Write-IniOutput($InputObject)
{
    foreach ($i in $InputObject.keys)
    {
        if (!($($InputObject[$i].GetType().Name) -eq "Hashtable"))
        {
            #No Sections
            Write-Output "$i=$($InputObject[$i])"
        } else {
            #Sections
            Write-Output "[$i]"
            Foreach ($j in ($InputObject[$i].keys | Sort-Object))
            {
                if ($j -match "^Comment[\d]+") {
                    Write-Output "$($InputObject[$i][$j])"
                } else {
                    Write-Output "$j=$($InputObject[$i][$j])"
                }
            }
            Write-Output ""
        }
    }
}

function Invoke-WslCommand
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Command,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = "DistributionName", Position = 1)]
        [SupportsWildCards()]
        [string[]]$DistributionName,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = "Distribution")]
        [WslDistribution[]]$Distribution,

        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string]$User
    )

    process {
        if ($PSCmdlet.ParameterSetName -eq "DistributionName") {
            if ($DistributionName) {
                $Distribution = Get-WslDistribution $DistributionName
            } else {
                $Distribution = Get-WslDistribution -Default
            }
        } elseif ($PSCmdLet.ParameterSetName -ne "Distribution") {
            $Distribution = Get-WslDistribution -Default
        }

        $Distribution | ForEach-Object {
            $DistroName = $_.Name
            $wslargs = @("--distribution", $DistroName)
            if ($User) {
                $wslargs += @("--user", $User)
            }

            $Command = $Command + "`n" # Add a trailing new line
            $Command = $Command.Replace("`r`n", "`n") # Replace Windows newlines with Unix ones
            $Command += '#' # Add a comment on the last line to hide PowerShell cruft added to the end of the string

            if ($PSCmdlet.ShouldProcess($DistroName, "Invoke Command")) {
                $Command | &$wslPath @wslargs /bin/sh
                if ($LASTEXITCODE -ne 0) {
                    # Note: this could be the exit code of wsl.exe, or of the launched command.
                    throw "Wsl.exe returned exit code $LASTEXITCODE from distro: ${DistroName}"
                }    
            }
        }
    }
}

function Add-WslFileContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Content,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [WslDistribution[]]$Distribution,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$User,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$File
    )

    $commandArgs = @{}
    if ($User) {
        $commandArgs = @{User = $User}
    }

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
    $base64 = [Convert]::ToBase64String($bytes)

    $Directory = ($File | Split-Path).Replace('\', '/')

    $Command = "mkdir -p `"$Directory`" && echo '$base64' | base64 -d > `"$File`""
    Invoke-WslCommand -Distribution $Distribution @commandArgs -Command $Command
}

function Add-WslFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [WslDistribution[]]$Distribution,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$User,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$File,

        [Parameter(Mandatory=$false)]
        $Replacements
    )

    $Path = $Path.Trim()
    $File = $File.Trim()
    if ($Path -and $File) {
        $Content = ""
        if ($Path.StartsWith("http://") -or $Path.StartsWith("https://")) {
            Write-Debug "*** Downloading $Path"
            $response = Invoke-WebRequest -Uri $Path -UseBasicParsing
            if ($response.StatusCode -eq 200) {
                if ($response.Headers['Content-Type'] -eq 'application/octet-stream') {
                    $Content = [Text.Encoding]::UTF8.GetString($response.content)
                } else {
                    $Content = $response.Content
                }
            } else {
                Write-Error $response.StatusCode
                throw
            }
        }
        if ($Content -and $Replacements) {
            $Replacements.keys | ForEach-Object {
                $Content = $Content.Replace($_, $Replacements[$_])
            }
        }
        $commandArgs = @{}
        if ($User) {
            $commandArgs = @{User = $User}
        }
        if ($Content) {
            $Content | Add-WslFileContent -Distribution $Distribution -File $File @commandArgs
        }
    }
}

function Add-WslFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [WslDistribution[]]$Distribution,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $files,

        [Parameter(Mandatory=$false)]
        $Replacements,

        [Parameter(Mandatory=$false)]
        $User
    )

    if ($Files) {
        $Files.values | ForEach-Object {
            $file = $_
            try {
                $source = $repoUrl.Trim() + $file.source.Trim()
                $destfile = $file.dest.Trim()
                $commandArgs = @{}
                if ($file['user']) {
                    $commandArgs = @{User = $file.user}
                } elseif ($User) {
                    $commandArgs = @{User = $User}
                }
                Write-Debug "+++ Adding file `"${destfile}`" from `"$source`""
                Add-WslFile -Distribution $Distribution -Path $source -File $destfile -Replacements $Replacements @commandArgs
            } catch {
                Write-Error $_
                if ($file.errorIsFatal) {
                    Remove-Installation -Distribution $Distribution
                    throw $file.errorMessage
                } else {
                    Write-Error -Message $file.errorMessage
                }
            }
        }
    }
}

function Remove-WslFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        $Files,
    
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [WslDistribution[]]$Distribution,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$User
    )

    process {
        foreach ($file in $Files) {
            $remove = $file.dest
            $commandArgs = @{}
            if ($file['user']) {
                $commandArgs = @{User = $file.user}
            } elseif ($User) {
                $commandArgs = @{User = $User}
            }
            Invoke-WslCommand -Distribution $Distribution -Command "rm -f $remove" @commandArgs
        }
    }
}

function Remove-Installation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [WslDistribution[]]$Distribution
    )

    $files.values | Remove-WslFiles -Distribution $Distribution
    $agentfiles.values | Remove-WslFiles -Distribution $Distribution
}

function Format-Hyperlink {
    param(
        [Parameter(ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Uri] $Uri,

        [Parameter(Mandatory=$false, Position = 1)]
        [string] $Label
    )

    if (($PSVersionTable.PSVersion.Major -lt 6 -or $IsWindows) -and -not $Env:WT_SESSION) {
        # Fallback for Windows users not inside Windows Terminal
        if ($Label) {
            return "$Label ($Uri)"
        }
        return "$Uri"
    }

    if ($Label) {
        return "`e]8;;$Uri`e\$Label`e]8;;`e\"
    }

    return "$Uri"
}
