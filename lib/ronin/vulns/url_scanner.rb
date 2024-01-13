# frozen_string_literal: true
#
# ronin-vulns - A Ruby library for blind vulnerability testing.
#
# Copyright (c) 2022-2024 Hal Brodigan (postmodern.mod3 at gmail.com)
#
# ronin-vulns is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ronin-vulns is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with ronin-vulns.  If not, see <https://www.gnu.org/licenses/>.
#

require 'ronin/vulns/lfi'
require 'ronin/vulns/rfi'
require 'ronin/vulns/sqli'
require 'ronin/vulns/ssti'
require 'ronin/vulns/reflected_xss'
require 'ronin/vulns/open_redirect'
require 'ronin/vulns/command_injection'

module Ronin
  module Vulns
    #
    # Top-level module which scans a URL for all web vulnerabilities.
    #
    # ## Examples
    #
    #     require 'ronin/vulns/url_scanner'
    #
    #     Ronin::Vulns::URLScanner.scan(url) do |vuln|
    #       # ...
    #     end
    #
    #     vuln = Ronin::Vulns::URLScanner.test(url)
    #
    module URLScanner
      #
      # Scans a URL for web vulnerabilities.
      #
      # @param [URI::HTTP, String] url
      #   The URL to test or exploit.
      #
      # @option kwargs [String, Symbol, nil] :query_param
      #   The query param to test or exploit.
      #
      # @option kwargs [String, Symbol, nil] :header_name
      #   The HTTP Header name to test or exploit.
      #
      # @option kwargs [String, Symbol, nil] :cookie_param
      #   The `Cookie:` param name to test or exploit.
      #
      # @option kwargs [String, Symbol, nil] :form_param
      #   The form param name to test or exploit.
      #
      # @option kwargs [Ronin::Support::Network::HTTP, nil] :http
      #   An HTTP session to use for testing the URL.
      #
      # @option kwargs [:copy, :delete, :get, :head, :lock, :mkcol, :move,
      #         :options, :patch, :post, :propfind, :proppatch, :put,
      #         :trace, :unlock] :request_method
      #   The HTTP request mehtod for each request.
      #
      # @option kwargs [String, nil] :user
      #   The user to authenticate as.
      #
      # @option kwargs [String, nil] :password
      #   The password to authenticate with.
      #
      # @option kwargs [Hash{Symbol,String => String}, nil] :headers
      #   Additional HTTP header names and values to add to the request.
      #
      # @option kwargs [String, Hash{String => String}, nil] :cookie
      #   Additional `Cookie` header. If a `Hash` is given, it will be
      #   converted to a `String` using `Ronin::Support::Network::HTTP::Cookie`.
      #
      # @option kwargs [Hash, String, nil] :form_data
      #   The form data that may be sent in the body of the request.
      #
      # @option kwargs [String, nil] :referer
      #   The optional HTTP `Referer` header to send with each request.
      #
      # @param [Hash{Symbol => Object}, false] lfi
      #   Additional options for {LFI.scan}.
      #
      # @option lfi [:unix, :windows, nil] :os (:unix)
      #   Operating System to specifically target.
      #
      # @option lfi [Integer] :depth (6)
      #   Number of directories to escape up.
      #
      # @option lfi [:null_byte, :double_escape, :base64, :rot13, :zlib, nil] :filter_bypass
      #   Specifies which filter bypass technique to use.
      #
      #   * `:null_byte - appends a `%00` null byte to the escaped path.
      #     **Note:* this technique only works on PHP < 5.3.
      #   * `:double_escape` - Double escapes the {LFI#escape_path}
      #     (ex: `....//....//`).
      #   * `:base64` - Base64 encodes the included local file.
      #   * `:rot13` - ROT13 encodes the included local file.
      #   * `:zlib` - Zlib compresses and Base64 encodes the included local
      #     file.
      #
      # @param [Hash{Symbol => Object}, false] rfi
      #   Additional options for {RFI.scan}.
      #
      # @option rfi [:null_byte, :double_encode, nil] :filter_bypass
      #   Specifies which filter bypass technique to use.
      #   * `:double_encode` - will cause the inclusion URL to be URI escaped
      #     twice.
      #   * `:suffix_escape` - escape any appended suffix (ex: `param + ".php"`)
      #     by adding a URI fragment character (`#`) to the end of the RFI
      #     script URL. The fragment component of the URI is not sent to the
      #     web server.
      #   * `:null_byte` - will cause the inclusion URL to be appended with a
      #     `%00` character. **Note:* this technique only works on PHP < 5.3.
      #
      # @option rfi [String, URI::HTTP, nil] :test_script_url
      #   The URL of the RFI test script. If not specified, it will default to
      #   {RFI.test_script_for}.
      #
      # @param [Hash{Symbol => Object}, false] sqli
      #   Additional options for {SQLI.scan}.
      #
      # @option sqli [Boolean] :escape_quote (false)
      #   Specifies whether to escape a quoted string value.
      #
      # @option sqli [Boolean] :escape_parens (false)
      #   Specifies whether to escape parenthesis.
      #
      # @option sqli [Boolean] :terminate (false)
      #   Specifies whether to terminate the SQL statement with `--`.
      #
      # @param [Hash{Symbol => Object}, false] ssti
      #   Additional options for {SSTI.scan}.
      #
      # @option ssti [Proc, nil] :escape
      #   How to escape a given payload. Either a proc that will accept a String
      #   and return a String, or `nil` to indicate that the payload will not
      #   be escaped.
      #
      # @option ssti [(String, String)] :test
      #   The test payload and expected result to check for when testing the URL
      #   for SSTI.
      #
      # @param [Hash{Symbol => Object}, false] reflected_xss
      #   Additional options for {ReflectedXSS.scan}.
      #
      # @param [Hash{Symbol => Object}, false] open_redirect
      #   Additional options for {OpenRedirect.scan}.
      #
      # @option open_redirect [String] :test_url (OpenRedirect.random_test_url)
      #   The desired redirect URL to test the URL with.
      #
      # @param [Hash{Symbol => Object}, false] command_injection
      #   Additional options for {CommandInjection.scan}.
      #
      # @yield [vuln]
      #   If a block is given it will be yielded each discovered web
      #   vulnerability.
      #
      # @yieldparam [LFI, RFI, SQLI, SSTI, ReflectedXSS, OpenRedirect] vuln
      #   A discovered web vulnerability in the URL.
      #
      # @return [Array<LFI, RFI, SQLI, SSTI, ReflectedXSS, OpenRedirect>]
      #   All discovered Web vulnerabilities.
      #
      def self.scan(url, lfi:  {},
                         rfi:  {},
                         sqli: {},
                         ssti: {},
                         reflected_xss: {},
                         open_redirect: {},
                         command_injection: {},
                         **kwargs,
                         &block)
        vulns = []

        if lfi
          vulns.concat(LFI.scan(url,**kwargs,**lfi,&block))
        end

        if rfi
          vulns.concat(RFI.scan(url,**kwargs,**rfi,&block))
        end

        if sqli
          vulns.concat(SQLI.scan(url,**kwargs,**sqli,&block))
        end

        if ssti
          vulns.concat(SSTI.scan(url,**kwargs,**ssti,&block))
        end

        if reflected_xss
          vulns.concat(ReflectedXSS.scan(url,**kwargs,**reflected_xss,&block))
        end

        if open_redirect
          vulns.concat(OpenRedirect.scan(url,**kwargs,**open_redirect,&block))
        end

        if command_injection
          vulns.concat(CommandInjection.scan(url,**kwargs,**command_injection,&block))
        end

        return vulns
      end

      #
      # Tests the URL for a Web vulnerability and returns the first found
      # vulnerability.
      #
      # @param [URI::HTTP, String] url
      #   The URL to test.
      #
      # @param [Hash{Symbol => Object}] kwargs
      #   Additional keyword arguments for {scan}.
      #
      # @return [LFI, RFI, SQLI, SSTI, ReflectedXSS, OpenRedirect, nil]
      #   The first discovered web vulnerability or `nil` if no vulnerabilities
      #   were discovered.
      #
      def self.test(url,**kwargs)
        scan(url,**kwargs) do |vuln|
          return vuln
        end

        return nil
      end
    end
  end
end
