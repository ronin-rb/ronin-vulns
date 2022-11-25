# ronin-vulns-rfi 1 "May 2022" Ronin "User Manuals"

## SYNOPSIS

`ronin-vulns rfi` [*options*] {*URL* ... \| `--input` *FILE*}

## DESCRIPTION

Scans URL(s) for Remote File Inclusion (RFI) vulnerabilities. The URLs to scan
can be given as additional arguments or read from a file using the `--input`
option.

## ARGUMENTS

*URL*
  A URL to scan.

## OPTIONS

`--first`
  Only find the first vulnerability for each URL.

`-A`, `--all`
  Find all vulnerabilities for each URL.

`-H`, `--header` "*Name*: *value*"
  Sets an additional header using the given *Name* and *value*.

`-C`, `--cookie` *COOKIE*
  Sets the raw `Cookie` header.

`-c`, `--cookie-param` *NAME*`=`*VALUE*
  Sets an additional `Cookie` param using the given *NAME* and *VALUE*.

`-R`, `--referer` *URL*
  Sets the `Referer` header.

`-F`, `--form-param` *NAME*`=`*VALUE*
  Sets an additional form param using the given *NAME* and *VALUE*.

`--test-query-param` *NAME*
  Tests the URL query param name.

`--test-all-query-params`
  Test all URL query param names.

`--test-header-name` *NAME*
  Tests the HTTP Header name.

`--test-cookie-param` *NAME*
  Tests the HTTP Cookie name.

`--test-all-cookie-params`
  Test all Cookie param names.

`--test-form-param` *NAME*
  Tests the form param name.

`-i`, `--input` *FILE*
  Reads URLs from the given *FILE*.

`-F`, `--filter-bypass` `double-encode`\|`suffix-escape`\|`null-byte`
  Optional filter-bypass strategy to use.

`-S`, `--script-lang` `asp\|`asp.net`\|`coldfusion`\|`jsp`\|`php`\|`perl`
  Explicitly specify the scripting language to test for.

`-T`, `--test-script-url` *URL*
  Use an altnerative test script *URL*.

`-h`, `--help`
  Print help information.

## AUTHOR

Postmodern <postmodern.mod3@gmail.com>

## SEE ALSO

ronin-vulns-scan(1)
