# frozen_string_literal: true
#
# ronin-vulns - A Ruby library for blind vulnerability testing.
#
# Copyright (c) 2022-2023 Hal Brodigan (postmodern.mod3 at gmail.com)
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

require 'ronin/vulns/web_vuln'
require 'ronin/vulns/version'

require 'ronin/support/network/http'
require 'uri/query_params'

module Ronin
  module Vulns
    #
    # Represents a Remote File Inclusion (RFI) vulnerability.
    #
    class RFI < WebVuln

      # The script extensions and their languages
      URL_EXTS = {
        '.asp'  => :asp,
        '.aspx' => :asp_net,
        '.cfm'  => :cold_fusion,
        '.cfml' => :cold_fusion,
        '.jsp'  => :jsp,
        '.php'  => :php,
        '.pl'   => :perl
      }

      # The github.com base URL for all RFI test scripts.
      GITHUB_BASE_URL = "https://raw.githubusercontent.com/ronin-rb/ronin-vulns/#{VERSION}/data"

      # Mapping of scripting languages to RFI test scripts.
      TEST_SCRIPT_URLS = {
        php:         "#{GITHUB_BASE_URL}/rfi_test.php",
        asp:         "#{GITHUB_BASE_URL}/rfi_test.asp",
        asp_net:     "#{GITHUB_BASE_URL}/rfi_test.aspx",
        jsp:         "#{GITHUB_BASE_URL}/rfi_test.jsp",
        cold_fusion: "#{GITHUB_BASE_URL}/rfi_test.cfm",
        perl:        "#{GITHUB_BASE_URL}/rfi_test.pl"
      }

      # The string that will be returned if the Remote File Inclusion (RFI)
      # script is executed.
      VULN_RESPONSE_STRING = "Security Alert: Remote File Inclusion Detected!"

      # The scripting language that the URL is using.
      #
      # @return [:asp, :asp_net, :cold_fusion, :jsp, :php, :perl, nil]
      #
      # @since 0.2.0
      attr_reader :script_lang

      # The filter bypass technique to use.
      #
      # @return [nil, :double_encode, :suffix_escape, :null_byte]
      attr_reader :filter_bypass

      # URL of the Remote File Inclusion (RFI) Test script
      #
      # @return [URI::HTTP, String]
      attr_reader :test_script_url

      #
      # Creates a new Remote File Inclusion (RFI) object.
      #
      # @param [String, URI::HTTP] url
      #   The URL to attempt to exploit.
      #
      # @param [:null_byte, :double_encode, nil] filter_bypass
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
      # @param [:asp, :asp_net, :cold_fusion, :jsp, :php, :perl, nil] script_lang
      #   Explicitly specifies the scripting language that the URL uses.
      #
      # @param [String, URI::HTTP, nil] test_script_url
      #   The URL of the RFI test script. If not specified, it will default to
      #   {test_script_for}.
      #
      def initialize(url, script_lang:     nil,
                          test_script_url: nil,
                          filter_bypass:   nil,
                          **kwargs)
        super(url,**kwargs)

        @script_lang = script_lang || self.class.infer_script_lang(@url)

        @test_script_url = if test_script_url
                             test_script_url
                           elsif @script_lang
                             self.class.test_script_url_for(@script_lang)
                           end

        @filter_bypass = filter_bypass
      end

      #
      # Returns the test script URL for the given scripting language.
      #
      # @param [:asp, :asp_net, :cold_fusion, :jsp, :php, :perl] script_lang
      #   The scripting language.
      #
      # @return [String]
      #   The test script URL for the given scripting language.
      #
      # @raise [ArgumentError]
      #   An unknown scripting language value was given.
      #
      def self.test_script_url_for(script_lang)
        TEST_SCRIPT_URLS.fetch(script_lang) do
          raise(ArgumentError,"unknown scripting language: #{script_lang.inspect}")
        end
      end

      #
      # Attempts to infer the programming language used for the web page at the
      # given URL.
      #
      # @param [String, URI::HTTP] url
      #   The URL to infer from.
      #
      # @return [:asp, :cold_fusion, :jsp, :php, :perl, nil]
      #   The programming language inferred from the URL.
      #
      def self.infer_script_lang(url)
        url = URI(url)

        return URL_EXTS[File.extname(url.path)]
      end

      #
      # Selects the RFI test script for the scripting language used by the given
      # URL.
      #
      # @param [String, URI::HTTP] url
      #   The URL to test.
      #
      # @return [String, nil]
      #   The RFI test script URL or `nil` if the scripting language could not
      #   be inferred from the URL.
      #
      def self.test_script_for(url)
        if (lang = infer_script_lang(url))
          TEST_SCRIPT_URLS.fetch(lang)
        end
      end

      #
      # Optionally applies a filter bypass technique to the RFI URL.
      #
      # @param [URI::HTTP, String] url
      #   The RFI URL to optionally encode before it will be injected into a
      #   HTTP request.
      #
      # @return [String]
      #   The optionally encoded RFI URL.
      #
      def encode_payload(url)
        url = url.to_s

        case @filter_bypass
        when :double_encode
          # Optionally double URI encodes the script URL
          url = URI::QueryParams.escape(url)
        when :suffix_escape
          # Optionally append a '#' character to escape any appended suffixes
          # (ex: `param + ".php"`).
          url = "#{url}#"
        when :null_byte
          # Optionally append a null-byte
          # NOTE: uri-query_params will automatically URI encode the null byte
          url = "#{url}\0"
        end

        return url
      end

      #
      # Tests whether the URL and query parameter are vulnerable to Remote File
      # Inclusion (RFI).
      #
      # @return [Boolean]
      #   Specifies whether the URL and query parameter are vulnerable to RFI.
      #
      def vulnerable?
        if @test_script_url
          test_a_test_script(@test_script_url)
        else
          test_each_test_script
        end
      end

      #
      # Determines if a specific test script URL can be remotely injected.
      #
      # @param [String] test_script_url
      #   The test script URL to attempt injecting.
      #
      # @return [Boolean]
      #   Indicates whether the test script was successfully executed or not.
      #
      # @api private
      #
      def test_a_test_script(test_script_url)
        response = exploit(test_script_url)
        body     = response.body

        return body.include?(VULN_RESPONSE_STRING)
      end

      #
      # Test each scripting language and RFI test payload in {TEST_SCRIPT_URLS}
      # until one succeeds.
      #
      # @return [Boolean]
      #   Indicates whether one of the test script was successfully executed or
      #   not.
      #
      # @note
      #   If one of the test script URLs successfully executes, then
      #   {#script_lang} and {#test_script_url} will be updated accordingly.
      #
      # @api private
      #
      def test_each_test_script
        TEST_SCRIPT_URLS.each do |script_lang,test_script_url|
          if test_a_test_script(test_script_url)
            @script_lang     = script_lang
            @test_script_url = test_script_url
            return true
          end
        end

        return false
      end

      #
      # Returns the type or kind of vulnerability.
      #
      # @return [Symbol]
      #
      # @note
      #   This is used internally to map an vulnerability class to a printable
      #   type.
      #
      # @api private
      #
      # @abstract
      #
      def self.vuln_type
        :rfi
      end

    end
  end
end
