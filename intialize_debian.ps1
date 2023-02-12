Using module Wsl

. $PSScriptRoot\lib.ps1

Write-Debug "--- Initial configuration"

Invoke-WslCommand -ErrorAction SilentlyContinue -DistributionName 'Debian' -User 'root' -Command @'
# configure dns
echo "[network]" | sudo tee -a /etc/wsl.conf
echo "generateResolvConf = false" | sudo tee -a /etc/wsl.conf
sudo chattr -i /etc/resolv.conf 
sudo rm -rf /etc/resolv.conf
echo "nameserver 172.20.242.68" | sudo tee /etc/resolv.conf
echo "nameserver 8.8.8.8" | sudo tee -a /etc/resolv.conf
echo "nameserver 8.8.8.4" | sudo tee -a /etc/resolv.conf
sudo chattr +i /etc/resolv.conf

# update all packages
apt update && apt upgrade -y

# install python3
apt install -y python3

# install ssh server
apt-get install -y openssh-server
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
service ssh restart
'@