# PowerShell completion for SecOps Helper
# Import: . .\completions\secops.ps1

$script:secopsCommands = @(
    'analyze', 'check', 'workflow', 'investigate', 'status',
    'list', 'info', 'search',
    'eml', 'ioc', 'hash', 'intel', 'log', 'pcap', 'url',
    'yara', 'cert', 'deobfuscate', 'feeds', 'carve'
)

$script:secopsWorkflows = @(
    'phishing-email', 'malware-triage', 'ioc-hunt',
    'network-forensics', 'log-investigation'
)

$script:secopsCheckTypes = @('hash', 'domain', 'ip', 'url')

$script:secopsFlags = @(
    '--verbose', '-v', '--json', '-j', '--quiet', '-q',
    '--report', '--output', '-o'
)

$script:secopsTools = @(
    'eml', 'ioc', 'hash', 'intel', 'log', 'pcap', 'url',
    'yara', 'cert', 'deobfuscate', 'feeds', 'carve'
)

Register-ArgumentCompleter -CommandName secops, secops.py -Native -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $tokens = $commandAst.ToString() -split '\s+'
    $tokenCount = $tokens.Count

    # Completing the subcommand (position 1)
    if ($tokenCount -le 2) {
        $script:secopsCommands | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
        return
    }

    $subCommand = $tokens[1]

    switch ($subCommand) {
        'analyze' {
            if ($wordToComplete.StartsWith('-')) {
                @('--verbose', '-v', '--json', '-j', '--quiet', '-q', '--report', '--output', '-o') |
                    Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                    }
            }
        }
        'check' {
            if ($tokenCount -le 3) {
                $script:secopsCheckTypes | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                }
            } elseif ($wordToComplete.StartsWith('-')) {
                @('--verbose', '-v', '--json', '-j') |
                    Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                    }
            }
        }
        'workflow' {
            if ($tokenCount -le 3) {
                $script:secopsWorkflows | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                }
            } elseif ($wordToComplete.StartsWith('-')) {
                @('--verbose', '-v', '--json', '-j', '--report', '--output', '-o') |
                    Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                    }
            }
        }
        'info' {
            $script:secopsTools | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
            }
        }
        'search' {
            # No completions for search keywords
        }
    }
}

# Also register for "python secops.py" invocation
Register-ArgumentCompleter -CommandName python -Native -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $tokens = $commandAst.ToString() -split '\s+'

    # Only activate if second token is secops.py
    if ($tokens.Count -ge 2 -and $tokens[1] -like '*secops.py') {
        $tokenCount = $tokens.Count

        if ($tokenCount -le 3) {
            $script:secopsCommands | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
            }
            return
        }

        $subCommand = $tokens[2]

        switch ($subCommand) {
            'check' {
                if ($tokenCount -le 4) {
                    $script:secopsCheckTypes | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                    }
                }
            }
            'workflow' {
                if ($tokenCount -le 4) {
                    $script:secopsWorkflows | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                    }
                }
            }
            'info' {
                $script:secopsTools | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                }
            }
        }
    }
}
