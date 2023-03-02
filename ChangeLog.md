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

