#!/bin/bash
#
# burp_update.sh
#
# Automate some of the steps of updating Burp Suite. Assumes you downloaded the installer
# into ~/Downloads.
#

# check whether burp is running
if [[ ! -z $(pgrep --full BurpSuite) ]]; then
    echo 'BurpSuite is running.'
    echo -n 'Kill? [y/N] '
    read answer
    if [[ "${answer,,}" == 'y' ]]; then
        echo 'Killing.'
        pkill --full -2 BurpSuite
    else
        echo 'Exiting. Please kill Burp manually and re-run.'
        exit 1
    fi                                                                                                                                                     
else                                                                                                                                                       
    echo 'BurpSuite does not appear to be running.'                                                                                                        
fi                                                                                                                                                                                                            
                                                                                                                                                                                                              
# find and confirm install file                                                                                                                                                                               
install_file=$(ls -t ~/Downloads/burpsuite_pro_linux_v202*_*.sh | head -1)                                                                                                                                    
if [[ ! -z "$install_file" ]]; then                                                                                                                                                                           
    echo "Install file found: $install_file"                                                                                                                                                                  
    echo -n 'Use this one? [Y/n] '                                                                                                                                                                            
    read answer                                                                                                                                                                                               
    if [[ "${answer,,}" == 'n' ]]; then                                                                                                                                                                       
        echo 'Please download the correct file, remove others, and re-run.'                                                                                                                                   
        exit 2                                                                                                                                                                                                
    else                                                                                                                                                                                                      
        echo 'Launching installer.'
    fi
else
    echo 'No install file found in Downloads.'
    echo 'Please download and re-run.'
    exit 3
fi

# launch update
sudo bash "$install_file"

# confirm whether to remove installer
echo -n 'Remove install file? [Y/n] '
read answer
if [[ "${answer,,}" == 'n' ]]; then
    echo 'Not removing.'
else
    echo 'Removing.'
    rm -v "$install_file"
fi
