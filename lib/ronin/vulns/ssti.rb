#
# ronin-vulns - A Ruby library for blind vulnerability testing.
#
# Copyright (c) 2022 Hal Brodigan (postmodern.mod3 at gmail.com)
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

require 'ronin/vulns/web'

module Ronin
  module Vulns
    #
    # Represents a Server Side Template Injection (SSTI) vulnerability.
    #
    class SSTI < Web

      # List of common Server Side Template Injection (SSTI) escapes.
      #
      # @api private
      ESCAPES = [
        nil, # does not escape the payload
        ->(payload) { "{{#{payload}}}"    },
        ->(payload) { "${#{payload}}"     },
        ->(payload) { "${{#{payload}}}"   },
        ->(payload) { "\#{#{payload}}"    },
        ->(payload) { "<%= #{payload} %>" }
      ]

      # How to escape the payload so that it's executed.
      #
      # @return [Proc, nil]
      #   The proc that will accept a String and return a String, or `nil` to
      #   indicate that the payload will not be escaped.
      attr_reader :escape

      # The payload to test the URL with.
      #
      # @return [String]
      attr_reader :test_payload

      # The expected result to check for when testing the URL for SSTI.
      #
      # @return [String]
      attr_reader :test_result

      #
      # Initializes the Server Side Template Injection (SSTI) vulnerability.
      #
      # @param [String, URI::HTTP] url
      #   The URL to exploit.
      #
      # @param [Proc, nil] escape
      #   How to escape a given payload. Either a proc that will accept a String
      #   and return a String, or `nil` to indicate that the payload will not
      #   be escaped.
      #
      # @param [(String, String)] test
      #   The test payload and expected result to check for when testing the URL
      #   for SSTI.
      #
      def initialize(url, escape: nil, test: self.class.random_test, **kwargs)
        super(url,**kwargs)

        @escape = escape

        @test_payload, @test_result = test

        unless (@test_payload && @test_result)
          raise(ArgumentError,"must specify both a test payload and a test result")
        end
      end

      #
      # Generates a random `N*M` SSTI test.
      #
      # @return [(String, String)]
      #   The test payload and expected result.
      #
      def self.random_test
        int1 = rand(999) + 1_000
        int2 = rand(999) + 1_000

        payload = "#{int1}*#{int2}"
        result  = (int1 * int2).to_s

        return [payload, result]
      end

      #
      # Scans the URL for Server Side Template Injection (SSTI) vulnerabilities.
      #
      # @param [URI::HTTP, String] url
      #   The URL to scan.
      #
      # @param [Hash{Symbol => Object}] kwargs
      #   Additional keyword arguments for {#initialize}.
      #
      # @option kwargs [Proc, nil] :escape
      #   The escape method to use. If `escape:` is not given, then all escapes
      #   in {ESCAPES} will be tested..
      #   
      # @option kwargs [Array<Symbol, String>, Symbol, String, true, nil] :query_params
      #   The query param name(s) to test.
      #
      # @option kwargs [Array<Symbol, String>, Symbol, String, nil] :header_names
      #   The header name(s) to test.
      #
      # @option kwargs [Array<Symbol, String>, Symbol, String, true, nil] :cookie_params
      #   The cookie param name(s) to test.
      #
      # @option kwargs [Array<Symbol, String>, Symbol, String, nil] :form_params
      #   The form param name(s) to test.
      #
      # @option kwargs [Ronin::Support::Network::HTTP, nil] :http
      #   An HTTP session to use for testing the LFI.
      #
      # @option kwargs [Hash{String => String}, nil] :headers
      #   Additional headers to send with requests.
      #
      # @option kwargs [String, Ronin::Support::Network::HTTP::Cookie, nil] :cookie
      #   Additional cookie params to send with requests.
      #
      # @option kwargs [String, nil] :referer
      #   Optional `Referer` header to send with requests.
      #
      # @option kwargs [Hash{String => String}, nil] :form_data
      #   Additional form data to send with requests.
      #
      # @yield [vuln]
      #   If a block is given it will be yielded each discovered vulnerability.
      #
      # @yieldparam [SSTI] vuln
      #   A discovered SSTI vulnerability in the URL.
      #
      # @return [Array<SSTI>]
      #   All discovered SSTI vulnerabilities.
      #
      def self.scan(url, **kwargs,&block)
        if kwargs.has_key?(:escape)
          super(url, **kwargs, &block)
        else
          ESCAPES.each do |escape|
            super(url, escape: escape, **kwargs, &block)
          end
        end
      end

      #
      # Escapes the payload using {#escape}.
      #
      # @param [String] payload
      #
      # @return [String]
      #
      def encode_payload(payload)
        if @escape then @escape.call(payload)
        else            payload
        end
      end

      #
      # Exploits the Server Side Template Injection (SSTI) vulnerability by
      # performing an HTTP request with the given template expression.
      #
      # @param [String] payload
      #   The template expression to attempt to execute.
      #
      # @return [Net::HTTPResponse]
      #   The HTTP response for the SSTI request.
      #
      def exploit(payload,**kwargs)
        super(encode_payload(payload),**kwargs)
      end

      #
      # Determine whether the URL is vulnerable to Server Side Template
      # Injection (SSTI).
      #
      # @return [Boolean]
      #
      def vulnerable?
        response = exploit(@test_payload)
        body     = response.body

        return body.include?(@test_result)
      end

    end
  end
end