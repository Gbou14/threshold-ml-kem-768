#!/usr/bin/env bash
# setup_ubuntu.sh — Run this ONCE on your Ubuntu VM to install Docker + Compose
# Usage: chmod +x setup_ubuntu.sh && sudo ./setup_ubuntu.sh

set -euo pipefail

echo "==> Updating package index..."
apt-get update -qq

echo "==> Installing prerequisites..."
apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

echo "==> Adding Docker's official GPG key..."
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo "==> Adding Docker apt repository..."
echo \
  "deb [arch=$(dpkg --print-architecture) \
       signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" \
  > /etc/apt/sources.list.d/docker.list

echo "==> Installing Docker Engine + Compose plugin..."
apt-get update -qq
apt-get install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin

echo "==> Starting and enabling Docker..."
systemctl enable --now docker

# Allow current user to use docker without sudo (re-login required)
SUDO_USER="${SUDO_USER:-$USER}"
if [ "$SUDO_USER" != "root" ]; then
    usermod -aG docker "$SUDO_USER"
    echo "==> Added $SUDO_USER to the docker group."
    echo "    ⚠  Log out and back in (or run: newgrp docker) for this to take effect."
fi

echo ""
echo "✓ Docker $(docker --version) installed"
echo "✓ Docker Compose $(docker compose version) installed"
echo ""
echo "Next step:"
echo "  cd shamir-docker && docker compose up --build"
