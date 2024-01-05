# ronin-vulns 1 "2024-01-01" Ronin Vulns "User Manuals"

## NAME

ronin-vulns - A library and tool that tests for various web vulnerabilities.

## SYNOPSIS

`ronin-vulns` [*options*] [*COMMAND* [...]]

## DESCRIPTION

Runs a `ronin-vulns` *COMMAND*.

## ARGUMENTS

*COMMAND*
: The `ronin-vulns` command to execute.

## OPTIONS

`-V`, `--version`
: Prints the `ronin-vulns` version and exits.

`-h`, `--help`
: Print help information

## COMMANDS

*command-injection*, *cmdi*
: Scans URL(s) for Command Injection vulnerabilities.

*completion*
: Manages the shell completion rules for `ronin-vulns`.

*help*
: Lists available commands or shows help about a specific command.

*lfi*
: Scans URL(s) for Local File Inclusion (LFI) vulnerabilities.

*open-redirect*
: Scans URL(s) for Open Redirect vulnerabilities.

*reflected-xss*, *xss*
: Scans URL(s) for Reflected Cross Site Scripting (XSS) vulnerabilities.

*rfi*
: Scans URL(s) for Remote File Inclusion (RFI) vulnerabilities.

*scan*
: Scans URL(s) for web vulnerabilities.

*sqli*
: Scans URL(s) for SQL injection (SQLi) vulnerabilities.

*ssti*
: Scans URL(s) for Server Side Template Injection (SSTI) vulnerabilities.

## AUTHOR

Postmodern <postmodern.mod3@gmail.com>

## SEE ALSO

[ronin-vulns-command-injection](ronin-vulns-command-injection.1.md) [ronin-vulns-completion](ronin-vulns-completion.1.md) [ronin-vulns-lfi](ronin-vulns-lfi.1.md) [ronin-vulns-open-redirect](ronin-vulns-open-redirect.1.md) [ronin-vulns-reflected-xss](ronin-vulns-reflected-xss.1.md) [ronin-vulns-rfi](ronin-vulns-rfi.1.md) [ronin-vulns-scan](ronin-vulns-scan.1.md) [ronin-vulns-sqli](ronin-vulns-sqli.1.md) [ronin-vulns-ssti](ronin-vulns-ssti.1.md) 
