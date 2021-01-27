#!/bin/bash

# Copyright (c) 2021  Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

VERSION="1.0"

# Warning! Be sure to download the latest version of this script from its primary source:

BULLETIN="https://access.redhat.com/security/vulnerabilities/RHSB-2021-002"

# DO NOT blindly trust any internet sources and NEVER do `curl something | bash`!

# This script is meant for simple detection of the vulnerability. Feel free to modify it for your
# environment or needs. For more advanced detection, consider Red Hat Insights:
# https://access.redhat.com/products/red-hat-insights#getstarted

# Checking against the list of vulnerable packages is necessary because of the way how features
# are back-ported to older versions of packages in various channels.


VULNERABLE_VERSIONS=(
    'sudo-1.8.6p7-13.ael7b'
    'sudo-1.6.8p12-12.el5'
    'sudo-1.6.9p17-3.el5'
    'sudo-1.6.9p17-3.el5_3.1'
    'sudo-1.6.9p17-5.el5'
    'sudo-1.6.9p17-6.el5_4'
    'sudo-1.7.2p1-5.el5'
    'sudo-1.7.2p1-6.el5_5'
    'sudo-1.7.2p1-7.el5_5'
    'sudo-1.7.2p1-8.el5_5'
    'sudo-1.7.2p1-9.el5_5'
    'sudo-1.7.2p1-10.el5'
    'sudo-1.7.2p1-13.el5'
    'sudo-1.7.2p1-14.el5_8.2'
    'sudo-1.7.2p1-14.el5_8.3'
    'sudo-1.7.2p1-14.el5_8.4'
    'sudo-1.7.2p1-14.el5_8'
    'sudo-1.7.2p1-19.el5'
    'sudo-1.7.2p1-22.el5'
    'sudo-1.7.2p1-22.el5_9.1'
    'sudo-1.7.2p1-28.el5'
    'sudo-1.7.2p1-29.el5_10'
    'sudo-1.7.2p1-30.el5_11'
    'sudo-1.7.2p1-31.el5_11.1'
    'sudo-1.7.2p1-31.el5_11'
    'sudo-1.7.2p2-9.el6'
    'sudo-1.7.4p5-5.el6'
    'sudo-1.7.4p5-6.el6_1'
    'sudo-1.7.4p5-7.el6'
    'sudo-1.7.4p5-9.el6_2'
    'sudo-1.7.4p5-11.el6'
    'sudo-1.7.4p5-12.el6_3'
    'sudo-1.7.4p5-13.el6_3.1'
    'sudo-1.7.4p5-13.el6_3'
    'sudo-1.8.6p3-7.el6'
    'sudo-1.8.6p3-12.el6'
    'sudo-1.8.6p3-12.el6_5.2'
    'sudo-1.8.6p3-15.el6'
    'sudo-1.8.6p3-15.el6_6.2'
    'sudo-1.8.6p3-19.el6'
    'sudo-1.8.6p3-20.el6_7'
    'sudo-1.8.6p3-24.el6'
    'sudo-1.8.6p3-25.el6_8'
    'sudo-1.8.6p3-27.el6'
    'sudo-1.8.6p3-28.el6_9'
    'sudo-1.8.6p3-29.el6_9'
    'sudo-1.8.6p3-29.el6_10.2'
    'sudo-1.8.6p3-29.el6_10.3'
    'sudo-1.8.6p7-7.el7'
    'sudo-1.8.6p7-11.el7'
    'sudo-1.8.6p7-13.el7'
    'sudo-1.8.6p7-16.el7'
    'sudo-1.8.6p7-17.el7_2.2'
    'sudo-1.8.6p7-17.el7_2'
    'sudo-1.8.6p7-20.el7'
    'sudo-1.8.6p7-21.el7_3'
    'sudo-1.8.6p7-22.el7_3'
    'sudo-1.8.6p7-23.el7_3.2'
    'sudo-1.8.6p7-23.el7_3'
    'sudo-1.8.19p2-10.el7'
    'sudo-1.8.19p2-11.el7_4'
    'sudo-1.8.19p2-12.el7_4.1'
    'sudo-1.8.19p2-12.el7_4'
    'sudo-1.8.19p2-13.el7'
    'sudo-1.8.19p2-14.el7_5.1'
    'sudo-1.8.19p2-14.el7_5'
    'sudo-1.8.23-1.el7'
    'sudo-1.8.23-3.el7'
    'sudo-1.8.23-3.el7_6.1'
    'sudo-1.8.23-4.el7'
    'sudo-1.8.23-4.el7_7.1'
    'sudo-1.8.23-4.el7_7.2'
    'sudo-1.8.23-9.el7'
    'sudo-1.8.23-10.el7'
    'sudo-1.8.25p1-4.el8'
    'sudo-1.8.25p1-4.el8_0.1'
    'sudo-1.8.25p1-4.el8_0.2'
    'sudo-1.8.25p1-4.el8_0.3'
    'sudo-1.8.25p1-7.el8'
    'sudo-1.8.25p1-8.el8_1.1'
    'sudo-1.8.25p1-8.el8_1'
    'sudo-1.8.29-5.el8'
    'sudo-1.8.29-6.el8'
    'sudo-1.6.7p5-30.1.1'
    'sudo-1.6.7p5-30.1.3'
    'sudo-1.6.7p5-30.1.5'
    'sudo-1.6.7p5-30.1'
    'sudo-1.6.8p12-10'
)


get_installed_packages() {
    # Checks for installed packages. Compatible with RHEL5.
    #
    # Args:
    #     package_names - an array of package name strings
    #
    # Prints:
    #     Lines with N-V-R.A strings of the installed packages.

    local package_names=( "$@" )

    rpm -qa --queryformat="%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n" "${package_names[@]}"
}


check_package() {
    # Checks if installed package is in list of vulnerable packages.
    #
    # Args:
    #     installed_packages - installed packages string as returned by 'rpm -qa package'
    #                          (may be multiline)
    #     vulnerable_versions - an array of vulnerable versions
    #
    # Prints:
    #     First vulnerable package string as returned by 'rpm -qa package', or nothing

    # Convert to array, use word splitting on purpose
    # shellcheck disable=SC2206
    local installed_packages=( $1 )
    shift
    local vulnerable_versions=( "$@" )

    for tested_package in "${vulnerable_versions[@]}"; do
        for installed_package in "${installed_packages[@]}"; do
            installed_package_without_arch="${installed_package%.*}"
            if [[ "$installed_package_without_arch" == "$tested_package" ]]; then
                echo "$installed_package"
                return 0
            fi
        done
    done
}


basic_args() {
    # Parses basic commandline arguments and sets basic environment.
    #
    # Args:
    #     parameters - an array of commandline arguments
    #
    # Side effects:
    #     Exits if --help parameters is used
    #     Sets COLOR constants and debug variable

    local parameters=( "$@" )

    RED="\\033[1;31m"
    GREEN="\\033[1;32m"
    BOLD="\\033[1m"
    RESET="\\033[0m"
    for parameter in "${parameters[@]}"; do
        if [[ "$parameter" == "-h" || "$parameter" == "--help" ]]; then
            echo "Usage: $( basename "$0" ) [-n | --no-colors] [-d | --debug]"
            exit 1
        elif [[ "$parameter" == "-n" || "$parameter" == "--no-colors" ]]; then
            RED=""
            GREEN=""
            BOLD=""
            RESET=""
        elif [[ "$parameter" == "-d" || "$parameter" == "--debug" ]]; then
            debug=true
        fi
    done
}


basic_reqs() {
    # Prints common disclaimer and checks basic requirements.
    #
    # Args:
    #     CVE - string printed in the disclaimer
    #
    # Side effects:
    #     Exits when 'rpm' command is not available

    local CVE="$1"

    # Disclaimer
    echo
    echo -e "${BOLD}This script (v$VERSION) is primarily designed to detect $CVE on supported"
    echo -e "Red Hat Enterprise Linux systems and kernel packages."
    echo -e "Result may be inaccurate for other RPM based systems.${RESET}"
    echo

    # RPM is required
    if ! command -v rpm &> /dev/null; then
        echo "'rpm' command is required, but not installed. Exiting."
        exit 1
    fi
}


check_supported_kernel() {
    # Checks if running kernel is supported.
    #
    # Args:
    #     running_kernel - kernel string as returned by 'uname -r'
    #
    # Side effects:
    #     Exits when running kernel is obviously not supported

    local running_kernel="$1"

    # Check supported platform
    if [[ "$running_kernel" != *".el"[6-8]* ]]; then
        echo -e "${RED}This script is meant to be used only on RHEL 6-8.${RESET}"
        exit 1
    fi
}


get_rhel() {
    # Gets RHEL number.
    #
    # Args:
    #     running_kernel - kernel string as returned by 'uname -r'
    #
    # Prints:
    #     RHEL number, e.g. '5', '6', '7', or '8'

    local running_kernel="$1"

    local rhel
    rhel=$( sed -r -n 's/^.*el([[:digit:]]).*$/\1/p' <<< "$running_kernel" )
    echo "$rhel"
}


set_default_values() {
    result=0
}


parse_facts() {
    # Gathers all available information and stores it in global variables. Only store facts and
    # do not draw conclusion in this function for better maintainability.
    #
    # Side effects:
    #     Sets many global boolean flags and content variables

    result_installed_packages=$( get_installed_packages "sudo" )
}


draw_conclusions() {
    # Draws conclusions based on available system data.
    #
    # Side effects:
    #     Sets many global boolean flags and content variables

    vulnerable_package=$( check_package "$result_installed_packages" "${VULNERABLE_VERSIONS[@]}" )

    if [[ "$vulnerable_package" ]]; then
        result=1
    fi
}


debug_print() {
    # Prints selected variables when debugging is enabled.

    variables=( running_kernel rhel result_installed_packages vulnerable_package result )
    for variable in "${variables[@]}"; do
        echo "$variable = *${!variable}*"
    done
    echo
}


if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    basic_args "$@"
    basic_reqs "CVE-2021-3156"
    running_kernel=$( uname -r )
    check_supported_kernel "$running_kernel"

    rhel=$( get_rhel "$running_kernel" )

    set_default_values
    parse_facts
    draw_conclusions

    # Debug prints
    if [[ "$debug" ]]; then
        debug_print
    fi

    if [[ ! "$result_installed_packages" ]]; then
        echo -e "${GREEN}'sudo' is not installed${RESET}."
        exit 0
    fi

    # Results
    echo -e "Detected 'sudo' package: ${BOLD}$result_installed_packages${RESET}"
    if (( result )); then
        echo -e "${RED}This sudo version is vulnerable.${RESET}"
        echo -e "Follow $BULLETIN for advice."
    else
        echo -e "${GREEN}This sudo version is not vulnerable.${RESET}"
    fi

    exit "$result"
fi
