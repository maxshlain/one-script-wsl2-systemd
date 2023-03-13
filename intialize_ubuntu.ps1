Using module Wsl

. $PSScriptRoot\lib.ps1

Write-Debug "--- Initial Ubuntu configuration"

Invoke-WslCommand -ErrorAction SilentlyContinue -DistributionName 'Ubuntu-22.04' -User 'root' -Command @'
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
apt install -y wget

# install python3
apt install -y python3

# uninstall install ssh server
sudo service ssh stop && sudo apt-get --purge remove openssh-server
'@
