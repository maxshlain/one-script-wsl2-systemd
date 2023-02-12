Using module Wsl

. $PSScriptRoot\lib.ps1

param(
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]
    $Distro = 'Debian',

    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]
    $User = 'zadmin',

    [switch]
    $NoGPG,

    [switch]
    $NoKernel
)

$PSDefaultParameterValues['*:Encoding'] = 'utf8'

$repoUrl = 'https://raw.githubusercontent.com/diddledani/one-script-wsl2-systemd/main/'

# The main files to install.
$files = @{
    'systemd' = @{
        'source' = 'src/00-wsl2-systemd.sh';
        'dest' = '/etc/profile.d/00-wsl2-systemd.sh';
        'errorIsFatal' = $true;
        'errorMessage' = 'Could not fetch the systemd script. Aborting installation.';
        'user' = 'root';
    };
    'sudoers' = @{
        'source' = 'src/sudoers';
        'dest' = '/etc/sudoers.d/wsl2-systemd';
        'errorIsFatal' = $true;
        'errorMessage' = 'Could not fetch the sudoers file. Aborting installation.';
        'user' = 'root';
    };
    'wslview-desktop' = @{
        'source' = 'src/applications/wslview.desktop';
        'dest' = '/usr/share/applications/wslview.desktop';
        'errorIsFatal' = $false;
        'errorMessage' = 'Could not set up default file handler forwarding to Windows';
        'user' = 'root';
    };
    'user-runtime-dir' = @{
        'source' = 'src/systemd/user-runtime-dir.override';
        'dest' = '/etc/systemd/system/user-runtime-dir@.service.d/override.conf';
        'errorIsFatal' = $false;
        'errorMessage' = 'Could not install Wayland support - Snaps supporting Wayland will fail to launch';
        'user' = 'root';
    };
    'xwayland-service' = @{
        'source' = 'src/systemd/wsl2-xwayland.service';
        'dest' = '/etc/systemd/system/wsl2-xwayland.service';
        'errorIsFatal' = $false;
        'errorMessage' = 'Could not install XWayland support - GUI snaps will not work';
        'user' = 'root';
    };
    'xwayland-socket' = @{
        'source' = 'src/systemd/wsl2-xwayland.socket';
        'dest' = '/etc/systemd/system/wsl2-xwayland.socket';
        'errorIsFatal' = $false;
        'errorMessage' = 'Could not install XWayland support - GUI snaps will not work';
        'user' = 'root';
    };
    'systemd-boot.sh' = @{
        'source' = 'src/systemd-boot.sh';
        'dest' = '/usr/sbin/systemd-boot.sh';
        'errorIsFatal' = $true;
        'errorMessage' = 'Could not install systemd boot script - system will not function at all';
        'user' = 'root';
    };
}

# These are installed after the main files in the default user's home folder.
$gpgagent = @{
    'gpgagent' = @{
        'source' = 'src/profile.d/gpg-agent.sh';
        'dest' = '$HOME/.wslprofile.d/gpg-agent.sh'
        'errorMessage' = 'Could not fetch the GPG agent script. Continuing without it.'
    }
}
$sshagent = @{
    'sshagent' = @{
        'source' = 'src/profile.d/ssh-agent.sh';
        'dest' = '$HOME/.wslprofile.d/ssh-agent.sh'
        'errorMessage' = 'Could not fetch the SSH agent script. Continuing without it.'
    }
}

Write-Output "`r`n`n"
Write-Output "#########################################################"
Write-Output "#                                                       #"
Write-Output "#       One Script WSL2 Systemd enablement script       #"
Write-Output "#                                                       #"
Write-Output "#########################################################`n`n"

if ($PSVersionTable.PSEdition -eq "Core" -and -not $IsWindows) {
    Write-Output "This script must be run in Windows."
    exit
}

Write-Output "If you encounter issues, please rerun the script with ``-Debug``, then $(Format-Hyperlink -Uri "https://github.com/diddledani/one-script-wsl2-systemd/issues/new/choose" -Label "hold ctrl and click this link to file an issue...")`n`n"

Write-Output "---------------------------------------------------------`n`n"

if ($Distro -and -not ($Distribution = Get-WslDistribution -Name $Distro)) {
    Write-Error "!!! $Distro is not currently installed. Refusing to continue."
    exit
}
if (-not $Distribution -and -not ($Distribution = Get-WslDistribution -Default)) {
    Write-Error "!!! You do not have a default distribution. Refusing to continue."
    exit
}
if (-not $Distribution) {
    Write-Debug "--- No distro specified, using your default distro $($Distribution.Name)"
}

if (-not $User) {
    Write-Debug "--- Detecting default user in $($Distribution.Name)"
    try {
        $User = Invoke-WslCommand -Distribution $Distribution -Command "whoami"
    } catch {
        Write-Error "Cannot detect username of your account in $Distribution. Aborting."
        Write-Error $_
        exit
    }
}

$params = @{User = $User}

Write-Debug "--- Ensuring $User is a sudoer in $($Distribution.Name)"
Invoke-WslCommand -Distribution $Distribution -User 'root' -Command "groupadd --system sudo 2>/dev/null" -ErrorAction SilentlyContinue
Invoke-WslCommand -Distribution $Distribution -User 'root' -Command "usermod -a -G sudo $User 2>/dev/null" -ErrorAction SilentlyContinue

Write-Debug "--- Installing files in $($Distribution.Name)"
Invoke-WslCommand -Distribution $Distribution -Command 'mkdir -p $HOME/.ssh'
Add-WslFiles -Distribution $Distribution -Files $files @params

Write-Debug "--- Setting systemd to automatically start in $($Distribution.Name)"
$wslconfig = @{}
if (Test-Path -Path "$($Distribution.FileSystemPath)\etc\wsl.conf") {
    $wslconfig = Get-IniContent "$($Distribution.FileSystemPath)\etc\wsl.conf"
}
if (-not $wslconfig["boot"]) {
    $wslconfig["boot"] = @{}
}
if (-not $wslconfig["boot"]["command"]) {
    $wslconfig["boot"]["command"] = ""
}
$wslconfig.boot.command = "/bin/sh /usr/sbin/systemd-boot.sh"
(Write-IniOutput $wslconfig) -Join "`n" | Add-WslFileContent -Distribution $Distribution -User "root" -File "/etc/wsl.conf"

# Setup agent sockets
Write-Debug "--- Installing SSH, GPG, etc. agent scripts in $($Distribution.Name)"
Add-WslFiles -Distribution $Distribution -Files $sshagent @params
if (-not $NoGPG) {
    Add-WslFiles -Distribution $Distribution -Files $gpgagent @params
}

# Disable some systemd units that conflict with our setup
Write-Debug "--- Disabling conflicting systemd services in $($Distribution.Name)"
Invoke-WslCommand -Distribution $Distribution -User 'root' -Command 'ln -sf /dev/null /etc/systemd/user/dirmngr.service'
Invoke-WslCommand -Distribution $Distribution -User 'root' -Command 'ln -sf /dev/null /etc/systemd/user/dirmngr.socket'
Invoke-WslCommand -Distribution $Distribution -User 'root' -Command 'ln -sf /dev/null /etc/systemd/user/gpg-agent.service'
Invoke-WslCommand -Distribution $Distribution -User 'root' -Command 'ln -sf /dev/null /etc/systemd/user/gpg-agent.socket'
Invoke-WslCommand -Distribution $Distribution -User 'root' -Command 'ln -sf /dev/null /etc/systemd/user/gpg-agent-ssh.socket'
Invoke-WslCommand -Distribution $Distribution -User 'root' -Command 'ln -sf /dev/null /etc/systemd/user/gpg-agent-extra.socket'
Invoke-WslCommand -Distribution $Distribution -User 'root' -Command 'ln -sf /dev/null /etc/systemd/user/gpg-agent-browser.socket'
Invoke-WslCommand -Distribution $Distribution -User 'root' -Command 'ln -sf /dev/null /etc/systemd/user/ssh-agent.service'
Invoke-WslCommand -Distribution $Distribution -User 'root' -Command 'ln -sf /dev/null /etc/systemd/user/pulseaudio.service'
Invoke-WslCommand -Distribution $Distribution -User 'root' -Command 'ln -sf /dev/null /etc/systemd/user/pulseaudio.socket'
Invoke-WslCommand -Distribution $Distribution -User 'root' -Command 'ln -sf /dev/null /etc/systemd/system/ModemManager.service'
Invoke-WslCommand -Distribution $Distribution -User 'root' -Command 'ln -sf /dev/null /etc/systemd/system/NetworkManager.service'
Invoke-WslCommand -Distribution $Distribution -User 'root' -Command 'ln -sf /dev/null /etc/systemd/system/NetworkManager-wait-online.service'
Invoke-WslCommand -Distribution $Distribution -User 'root' -Command 'ln -sf /dev/null /etc/systemd/system/networkd-dispatcher.service'
Invoke-WslCommand -Distribution $Distribution -User 'root' -Command 'ln -sf /dev/null /etc/systemd/system/systemd-networkd.service'
Invoke-WslCommand -Distribution $Distribution -User 'root' -Command 'ln -sf /dev/null /etc/systemd/system/systemd-networkd-wait-online.service'
Invoke-WslCommand -Distribution $Distribution -User 'root' -Command 'ln -sf /dev/null /etc/systemd/system/systemd-resolved.service'

Write-Debug "--- Enabling custom systemd services in $($Distribution.Name)"
#Invoke-WslCommand -Distribution $Distribution -User 'root' -Command 'ln -sf ../wsl2-xwayland.socket /etc/systemd/system/sockets.target.wants/'

# Upgrade distribution packages first
Write-Debug "--- Attempting to install latest updates in $($Distribution.Name)"
Invoke-WslCommand -ErrorAction SilentlyContinue -Distribution $Distribution -User 'root' -Command @'
do_ubuntu() {
    do_apt
}
do_kali() {
    do_apt
}
do_apt() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get upgrade -yyq
}
do_apk() {
    apk update
    apk upgrade
}
do_sles() {
    do_zypper
}
do_zypper() {
    zypper --non-interactive update
}
if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "$ID" in
        "ubuntu")
            do_ubuntu ;;
        "kali")
            do_kali ;;
        "debian")
            do_apt ;;
        "alpine")
            do_apk ;;
        "sles")
            do_sles ;;
        *)
            case "$ID_LIKE" in
                *"debian"*)
                    do_apt ;;
                *"suse"*)
                    do_zypper ;;
                *)
            esac
            ;;
    esac
fi
'@

# Install systemd-container for access to machinectl executable
Write-Debug "--- Installing systemd-container in $($Distribution.Name)"
Invoke-WslCommand -ErrorAction SilentlyContinue -Distribution $Distribution -User 'root' -Command @'
do_ubuntu() {
    do_apt
}
do_kali() {
    do_apt
}
do_apt() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -yyq systemd-container
}
do_apk() {
    exit 0
}
do_sles() {
    do_zypper
}
do_zypper() {
    zypper --non-interactive install systemd-container
}
if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "$ID" in
        "ubuntu")
            do_ubuntu ;;
        "kali")
            do_kali ;;
        "debian")
            do_apt ;;
        "alpine")
            do_apk ;;
        "sles")
            do_sles ;;
        *)
            case "$ID_LIKE" in
                *"debian"*)
                    do_apt ;;
                *"suse"*)
                    do_zypper ;;
                *)
            esac
            ;;
    esac
fi
'@

# Install ZSH
Write-Debug "--- Installing ZSH in $($Distribution.Name)"
Invoke-WslCommand -ErrorAction SilentlyContinue -Distribution $Distribution -User 'root' -Command @'
do_ubuntu() {
    do_apt
}
do_kali() {
    do_apt
}
do_apt() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -yyq zsh
}
do_apk() {
    apk update
    apk add zsh
}
do_sles() {
    do_zypper
}
do_zypper() {
    zypper --non-interactive install zsh
}
if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "$ID" in
        "ubuntu")
            do_ubuntu ;;
        "kali")
            do_kali ;;
        "debian")
            do_apt ;;
        "alpine")
            do_apk ;;
        "sles")
            do_sles ;;
        *)
            case "$ID_LIKE" in
                *"debian"*)
                    do_apt ;;
                *"suse"*)
                    do_zypper ;;
                *)
            esac
            ;;
    esac
fi
'@
Write-Debug "--- Attempting to configure ZSH in $($Distribution.Name)"
Invoke-WslCommand -ErrorAction SilentlyContinue -Distribution $Distribution -User 'root' -Command @'
    if [ -f "/etc/zsh/zshenv" ]; then
        ZSHENVFILE=/etc/zsh/zshenv
    elif [ -f "/etc/zshenv" ]; then
        ZSHENVFILE=/etc/zshenv
    fi

    if [ -n "$ZSHENVFILE" ]; then
        if ! grep -q 00-wsl2-systemd.sh "$ZSHENVFILE"; then
            sed -i "1i[ -f '\/etc\/profile.d\/00-wsl2-systemd.sh' ] && emulate sh -c 'source \/etc\/profile.d\/00-wsl2-systemd.sh'" "$ZSHENVFILE"
        fi
    else
        echo "+++ Cannot find 'zshenv' file. ZSH is not configured for systemd."
    fi
'@

# Update the desktop mime database
Write-Debug "--- Updating desktop-file MIME database in $($Distribution.Name)"
Invoke-WslCommand -ErrorAction SilentlyContinue -Distribution $Distribution -User 'root' -Command @'
do_ubuntu() {
    do_apt
}
do_kali() {
    do_apt
}
do_apt() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -yyq desktop-file-utils
}
do_apk() {
    apk update
    apk add desktop-file-utils
}
do_sles() {
    do_zypper
}
do_zypper() {
    zypper --non-interactive install desktop-file-utils
}
if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "$ID" in
        "ubuntu")
            do_ubuntu ;;
        "kali")
            do_kali ;;
        "debian")
            do_apt ;;
        "alpine")
            do_apk ;;
        "sles")
            do_sles ;;
        *)
            case "$ID_LIKE" in
                *"debian"*)
                    do_apt ;;
                *"suse"*)
                    do_zypper ;;
                *)
            esac
            ;;
    esac
fi
if command -v update-desktop-database >/dev/null; then
    update-desktop-database
fi
'@

Write-Debug "--- Installing WSLUtilities in $($Distribution.Name)"
Invoke-WslCommand -ErrorAction SilentlyContinue -Distribution $Distribution -User 'root' -Command @'
do_ubuntu() {
    export DEBIAN_FRONTEND=noninteractive
    add-apt-repository -y ppa:wslutilities/wslu
    apt-get update
    apt-get install -yyq wslu
}
do_kali() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt install -yyq gnupg2 apt-transport-https
    wget -O - https://pkg.wslutiliti.es/public.key >> /etc/apt/trusted.gpg.d/wslu.asc
    echo "deb https://pkg.wslutiliti.es/kali kali-rolling main" >> /etc/apt/sources.list
    apt-get update
    apt-get install -yyq wslu
}
do_apt() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt install -yyq gnupg2 apt-transport-https
    wget -O - https://pkg.wslutiliti.es/public.key >> /etc/apt/trusted.gpg.d/wslu.asc
    echo "deb https://pkg.wslutiliti.es/debian buster main" >> /etc/apt/sources.list
    apt-get update
    apt-get install -yyq wslu
}
do_apk() {
    echo "@testing https://dl-cdn.alpinelinux.org/alpine/edge/community/" >> /etc/apk/repositories
    apk update
    apk add wslu@testing
}
do_sles() {
    SLESCUR_VERSION="$(grep VERSION= /etc/os-release | sed -e s/VERSION=//g -e s/\"//g -e s/-/_/g)"
    sudo zypper addrepo https://download.opensuse.org/repositories/home:/wslutilities/SLE_$SLESCUR_VERSION/home:wslutilities.repo
    sudo zypper addrepo https://download.opensuse.org/repositories/graphics/SLE_$SLESCUR_VERSION/graphics.repo
    zypper --non-interactive --no-gpg-checks install wslu
}
do_zypper() {
    zypper addrepo https://download.opensuse.org/repositories/home:/wslutilities/openSUSE_Leap_15.1/home:wslutilities.repo
    zypper --non-interactive install wslu
}
if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "$ID" in
        "ubuntu")
            do_ubuntu ;;
        "kali")
            do_kali ;;
        "debian")
            do_apt ;;
        "alpine")
            do_apk ;;
        "sles")
            do_sles ;;
        *)
            case "$ID_LIKE" in
                *"debian"*)
                    do_apt ;;
                *"suse"*)
                    do_zypper ;;
                *)
            esac
            ;;
    esac
fi
sed -Ei 's^(winps_exec "Write-Output \\\$)Env:\$\*(" | cat)^\1{Env:$*}\2^' /usr/bin/wslview
if command -v wslview >/dev/null; then
    wslview --reg-as-browser
fi
'@

# Install socat for GPG and SSH agent forwarding
Write-Debug "--- Installing socat in $($Distribution.Name)"
Invoke-WslCommand -ErrorAction SilentlyContinue -Distribution $Distribution -User 'root' -Command @'
do_ubuntu() {
    do_apt
}
do_kali() {
    do_apt
}
do_apt() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -yyq socat
}
do_apk() {
    apk update
    apk add socat
}
do_sles() {
    do_zypper
}
do_zypper() {
    zypper --non-interactive install socat
}
if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "$ID" in
        "ubuntu")
            do_ubuntu ;;
        "kali")
            do_kali ;;
        "debian")
            do_apt ;;
        "alpine")
            do_apk ;;
        "sles")
            do_sles ;;
        *)
            case "$ID_LIKE" in
                *"debian"*)
                    do_apt ;;
                *"suse"*)
                    do_zypper ;;
                *)
            esac
            ;;
    esac
fi
'@

# Install GPG4Win
if ($NoGPG) {
    Write-Debug 'Skipping Gpg4win installation'
} elseif (-not -not $(where.exe winget.exe)) {
    Write-Debug '--- Installing GPG4Win in Windows'
    try {
        winget.exe install --silent gnupg.Gpg4win
    } catch {}
} else {
    Write-Debug 'Cannot find winget.exe. Skipping Gpg4Win installation'
}

Write-Debug '--- Adding Windows scheduled tasks and starting services'

$adminScript = "$env:TEMP\setup-agent-services.ps1"
$response = Invoke-WebRequest -Uri "$repoUrl/src/setup-agent-services.ps1" -OutFile $adminScript -PassThru -UseBasicParsing
if ($response.StatusCode -eq 200) {
    $CmdArgs = @()
    if ($NoGPG) {
        $CmdArgs += @('-NoGPG')
    }
    if ($NoKernel) {
        $CmdArgs += @('-NoKernel')
    }
    try {
        Start-Process -Verb RunAs -Wait -FilePath $powershellProcess -Args '-NonInteractive', '-ExecutionPolicy', 'ByPass', '-Command', "$adminScript $CmdArgs"
    } catch {}
    Remove-Item $adminScript
} else {
    Write-Warning 'Could not fetch the script to set up your SSH & GPG Agents and update the custom WSL2 kernel'
}

Write-Output "`nDone."
if (-not $NoKernel) {
    Write-Output "If you want to go back to the Microsoft kernel open a PowerShell or CMD window and run:"
    Write-Output "`n`t$powershellProcess -NonInteractive -NoProfile -Command 'Start-Process' -Verb RunAs -FilePath $powershellProcess -ArgumentList '{ Unregister-ScheduledJob -Name UpdateWSL2CustomKernel }'"
}
Write-Output "`n"
Write-Output "You may now close this window..."
