#compdef secops

# Zsh completion for SecOps Helper
# Add to fpath or source directly: source completions/secops.zsh

_secops() {
    local -a commands workflows check_types tools

    commands=(
        'analyze:Smart analyze with auto-detection'
        'check:Quick indicator lookup'
        'workflow:Run pre-built investigation workflow'
        'investigate:Interactive guided investigation'
        'status:Show system status dashboard'
        'list:List all available tools'
        'info:Get detailed info about a tool'
        'search:Search for tools by keyword'
        'eml:Run EML Parser'
        'ioc:Run IOC Extractor'
        'hash:Run Hash Lookup'
        'intel:Run Domain/IP Intelligence'
        'log:Run Log Analyzer'
        'pcap:Run PCAP Analyzer'
        'url:Run URL Analyzer'
        'yara:Run YARA Scanner'
        'cert:Run Certificate Analyzer'
        'deobfuscate:Run Script Deobfuscator'
        'feeds:Run Threat Feed Aggregator'
        'carve:Run File Carver'
    )

    workflows=(
        'phishing-email:Comprehensive phishing email investigation'
        'malware-triage:Quick malware analysis and triage'
        'ioc-hunt:Bulk IOC threat hunting'
        'network-forensics:Network traffic forensic analysis'
        'log-investigation:Security log investigation'
    )

    check_types=(
        'hash:Look up file hash (MD5/SHA1/SHA256)'
        'domain:Get domain intelligence'
        'ip:Get IP intelligence'
        'url:Check URL reputation'
    )

    tools=(eml ioc hash intel log pcap url yara cert deobfuscate feeds carve)

    case "$words[2]" in
        analyze)
            _arguments \
                '--verbose[Verbose output]' \
                '-v[Verbose output]' \
                '--json[JSON output]' \
                '-j[JSON output]' \
                '--quiet[Minimal output]' \
                '-q[Minimal output]' \
                '--report[Generate report]:format:(html markdown md)' \
                '--output[Output path]:file:_files' \
                '-o[Output path]:file:_files' \
                '*:input:_files'
            ;;
        check)
            if (( CURRENT == 3 )); then
                _describe 'check type' check_types
                _files
            elif (( CURRENT == 4 )); then
                _message 'indicator value'
            else
                _arguments \
                    '--verbose[Verbose output]' \
                    '-v[Verbose output]' \
                    '--json[JSON output]' \
                    '-j[JSON output]'
            fi
            ;;
        workflow)
            if (( CURRENT == 3 )); then
                _describe 'workflow' workflows
            elif (( CURRENT == 4 )); then
                _files
            else
                _arguments \
                    '--verbose[Verbose output]' \
                    '-v[Verbose output]' \
                    '--json[JSON output]' \
                    '-j[JSON output]' \
                    '--report[Generate report]:format:(html markdown md)' \
                    '--output[Output path]:file:_files' \
                    '-o[Output path]:file:_files'
            fi
            ;;
        info)
            _describe 'tool' commands
            ;;
        search)
            _message 'search keyword'
            ;;
        *)
            _describe 'command' commands
            ;;
    esac
}

_secops "$@"
