### 0.2.1 / 2025-02-14

* Added the `base64` gem as a dependency for Bundler and Ruby 3.4.0.
* Added missing `ronin/vulns` Ruby file.
* Use `require_relative` to improve load times.
* Documentation fixes.

#### CLI

* Fixed a bug in the `ronin-vulns irb` command where the `ronin/vulns` Ruby file
  was missing.

### 0.2.0 / 2024-07-22

* Require [ronin-db] ~> 0.2
* Added {Ronin::Vulns::Importer}.
* Added the `user_agent:` keyword argument to
  {Ronin::Vulns::WebVuln#initialize}.
* Added {Ronin::Vulns::WebVuln#user_agent}.
* Added {Ronin::Vulns::CommandInjection}.
* Added the `command_injection:` keyword argument to
  {Ronin::Vulns::URLScanner.scan}.
* Added {Ronin::Vulns::RFI#script_lang}.
* Support inferring the {Ronin::Vulns::RFI#script_lang} from the URL given to
  {Ronin::Vulns::RFI#initialize}.
* Bruteforce test every different kind of RFI test URL in
  {Ronin::Vulns::RFI#vulnerable?} if a test script URL was not given or the
  {Ronin::Vulns::RFI#script_lang} cannot be inferred from the given URL.
* Allow the `escape_type:` keyword argument for {Ronin::Vulns::SSTI#initialize}
  to accept a Symbol value to specify the specific
  Server-Side-Template-Injection interpolation syntax:
  * `:double_curly_braces` - `{{expression}}`
  * `:dollar_curly_braces` - `${expression}`
  * `:dollar_double_curly_braces` - `${{expression}}`
  * `:pound_curly_braces` - `#{expression}`
  * `:angle_brackets_percent` - `<%= expression %>`

#### CLI

* Added the `ronin-vulns command-injection` command.
* Added the `ronin-vulns irb` command.
* Added the `ronin-vulns completion` command to install shell completion files
  for all `ronin-vulns` commands for Bash and Zsh shells.
* Added the `-H,--request-method` option to all commands.
* Added the `--user-agent` and `--user-agent-string` options to all commands.
* Added the `--test-all-form-params` option to all commands.
* Added the `--print-curl` and `--print-http` options to all commands.
* Added the `--import` option to all commands.
* Print a summary of all vulnerabilities found after scanning a URL, in addition
  to logging messages indicating when a new vulnerability has just been found.
* Use hyphenated values for the `--lfi-filter-bypass` option in the
  `ronin-vulns scan` command and `--filter-bypass` option in the
  `ronin-vulns lfi` command.

### 0.1.5 / 2024-06-19

* Improve the accuracy of {Ronin::Vulns::OpenRedirect#vulnerable?} when
  detecting open redirects in meta-refresh HTML tags.
  * Match the test URL when it ends with `?...`, `&...`, or `&amp;...`.
  * Detect when the test URL has an additional string appended to it
    (ex: `.html`). The appended string can easily be bypassed by adding a
    `?`, `&`, or `#` character to the end of the test URL.

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

[ronin-db]: https://github.com/ronin-rb/ronin-db#readme
