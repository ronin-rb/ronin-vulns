### 0.1.4 / 2023-09-19

#### CLI

* Improved the performance of `ronin-vulns` commands when scanning multiple URLs
  or a file of URLs by not rebuilding an identical
  {Ronin::Vulns::CLI::WebVulnCommand#scan_kwargs} for each URL.
* Allow the `--cookie "..."` option to be repeated multiple times and merge the
  cookie strings together.
* Allow the `--cookie-param NAME=VALUE` option to be used with the
  `--cookie "..."` option and merge the cookie values together.
* Print vulnerable param names in single quotes.

### 0.1.3 / 2023-07-07

* Fixed a bug in {Ronin::Vulns::SSTI.scan} where when called without `escape:`
  it would not return all found vulnerabilities.
* Fixed a bug in {Ronin::Vulns::SQLI.scan} where repeat requests would be sent
  even if `escape_quote:`, `escape_parens:`, or `terminate:` keyword arguments
  are given.
* Improved {Ronin::Vulns::ReflectedXSS::Context} to detect when the XSS occurs
  after or *inside of* an HTML comment.

### 0.1.2 / 2023-03-01

* Require `ronin-support` ~> 1.0, >= 1.0.1

#### CLI

* Validate that given URLs start with either `http://` or `https://`, and print
  an error message otherwise.
* Print a `No vulnerabilities found` message when no vulnerabilities were
  discovered.

### 0.1.1 / 2023-02-02

* Fixed typo in {Ronin::Vulns::CLI::WebVulnCommand#process_url} which effected
  the `ronin-vulns lfi` command and others.

### 0.1.0 / 2023-02-01

* Initial release:
  * Require `ruby` >= 3.0.0.
  * Supports testing for:
    * Local File Inclusion (LFI)
    * Remote File Inclusion (RFI)
      * PHP
      * ASP Class / ASP.NET
      * JSP
      * ColdFusion
      * Perl
    * SQL Injection (SQLi)
    * Reflected Cross Site Scripting (XSS)
    * Server Side Template Injection (SSTI)
    * Open Redirects
  * Supports testing:
    * URL query parameters.
    * HTTP Headers.
    * HTTP `Cookie` parameters.
    * Form parameters.

