# ronin-vulns-scan 1 "May 2022" Ronin "User Manuals"

## SYNOPSIS

`ronin-vulns scan` [*options*] {*URL* ... \| `--input` *FILE*}

## DESCRIPTION

Scans URL(s) for web vulnerabilities. The URLs to scan can be given as
additional arguments or read from a file using the `--input` option.

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

`--lfi-os` `unix`\|`windows`
  Sets the OS to test for.

`--lfi-depth` *NUM*
  Sets the directory depth to escape up.

`--lfi-filter-bypass` `null_byte`\|`double_escape`\|`base64`\|`rot13`\|`zlib`
  Sets the filter bypass strategy to use.

`--rfi-filter-bypass` `double-encode`\|`suffix-escape`\|`null-byte`
  Optional filter-bypass strategy to use.

`--rfi-script-lang` `asp`\|`asp.net`\|`coldfusion`\|`jsp`\|`php`\|`perl`
  Explicitly specify the scripting language to test for.

`--rfi-test-script-url` *URL*
  Use an altnerative test script URL.

`--sqli-escape-quote`
  Escapes quotation marks.

`--sqli-escape-parens`
  Escapes parenthesis.

`--sqli-terminate`
  Terminates the SQL expression with a `--`.

`--ssti-test-expr` {*X*\**Y* \| *X*/*Z* \| *X*+*Y* \| *X*-*Y*}
  Optional numeric test to use.

`--open-redirect-url` *URL*
  Optional test URL to try to redirect to.

`-h`, `--help`
  Print help information.

## AUTHOR

Postmodern <postmodern.mod3@gmail.com>

## SEE ALSO

ronin-vulns-lfi(1) ronin-vulns-rfi(1) ronin-vulns-sqli(1) ronin-vulns-ssti(1) ronin-vulns-open-redirect(1) ronin-vulns-reflected-xss(1)
