#!/bin/bash
# Bash completion for SecOps Helper
# Source this file: source completions/secops.bash

_secops_completions() {
    local cur prev commands workflows check_types tools flags
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # Top-level commands
    commands="analyze check workflow investigate status list info search eml ioc hash intel log pcap url yara cert deobfuscate feeds carve"

    # Workflow names
    workflows="phishing-email malware-triage ioc-hunt network-forensics log-investigation"

    # Check types
    check_types="hash domain ip url"

    # Tool names for info command
    tools="eml ioc hash intel log pcap url yara cert deobfuscate feeds carve"

    # Common flags
    flags="--verbose -v --json -j --quiet -q --report --output -o"

    case "${COMP_WORDS[1]}" in
        analyze)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--verbose -v --json -j --quiet -q --report --output -o" -- "$cur") )
            else
                # Complete file names
                COMPREPLY=( $(compgen -f -- "$cur") )
            fi
            ;;
        check)
            if [[ "$COMP_CWORD" -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "$check_types" -- "$cur") )
                # Also complete file names
                COMPREPLY+=( $(compgen -f -- "$cur") )
            elif [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--verbose -v --json -j" -- "$cur") )
            fi
            ;;
        workflow)
            if [[ "$COMP_CWORD" -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "$workflows" -- "$cur") )
            elif [[ "$COMP_CWORD" -eq 3 ]]; then
                COMPREPLY=( $(compgen -f -- "$cur") )
            elif [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--verbose -v --json -j --report --output -o" -- "$cur") )
            fi
            ;;
        info|search)
            if [[ "$COMP_CWORD" -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "$tools" -- "$cur") )
            fi
            ;;
        *)
            if [[ "$COMP_CWORD" -eq 1 ]]; then
                COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
            fi
            ;;
    esac

    return 0
}

complete -F _secops_completions secops
complete -F _secops_completions ./secops
complete -F _secops_completions python secops.py
