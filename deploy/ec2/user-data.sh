#!/bin/bash
# EC2 user data for Ubuntu 24.04: installs Docker Engine with the Compose plugin from Docker's
# apt repository and adds a 1 GiB swap file (a t3.micro has 1 GiB of RAM). Runs once, as root,
# on the first boot. See docs/DESPLIEGUE.md.
set -euo pipefail

apt-get update
apt-get install -y ca-certificates curl
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
# shellcheck source=/dev/null
. /etc/os-release
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# The deploy user runs docker compose; membership in the docker group is root-equivalent.
usermod -aG docker ubuntu

fallocate -l 1G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab
