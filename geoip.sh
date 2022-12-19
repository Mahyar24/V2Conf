#!/usr/bin/env bash

# GitHub: https://github.com/Mahyar24/V2Conf
# Mahyar@Mahyar24.com, Sun Nov 13 2022


dat_file_link="https://github.com/v2fly/geoip/releases/latest/download/geoip.dat"
dat_file_sha="https://github.com/v2fly/geoip/releases/latest/download/geoip.dat.sha256sum"


# Download the latest geoip.dat
function main() {
  # Downloading the main file
  if wget -c --tries=50 -O "/tmp/geoip.dat" "${dat_file_link}"; then
    # Downloading the SHA256SUM file
    if wget -c --tries=50 -O "/tmp/geoip.dat.sha256sum" "${dat_file_sha}"; then
      cd "/tmp" || exit 1
      # Checking the SHA256SUM
      if sha256sum -c --status "geoip.dat.sha256sum"; then
        # If the SHA256SUM is correct, then move the file to the correct location
        if mv -f "/tmp/geoip.dat" "/usr/local/share/v2ray/geoip.dat"; then
          rm -f "/tmp/geoip.dat.sha256sum"
          echo "geoip.dat updated successfully."
        else
          echo "Failed to move the file to the correct location."
          exit 1
        fi
      else
        echo "sha256sum check failed"
        exit 1
      fi
    else
      echo "Failed to download the SHA256SUM file."
      exit 1
    fi
  else
    echo "Failed to download the geoip.dat file."
    exit 1
  fi
}

main;


