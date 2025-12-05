#!/bin/bash
#
# upgrade_clean.sh
#
# On Debian-based systems, run all upgrades and clean up afterwards.
#

# main
sudo apt update
sudo apt-get -y --show-progress dist-upgrade
sudo apt-get -y --show-progress autoremove
sudo apt-get autoclean
