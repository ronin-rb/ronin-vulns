# frozen_string_literal: true
#
# ronin-vulns - A Ruby library for blind vulnerability testing.
#
# Copyright (c) 2022-2025 Hal Brodigan (postmodern.mod3 at gmail.com)
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

require_relative 'web_vuln'

require 'time'

module Ronin
  module Vulns
    #
    # Represents a Command Injection vulnerability.
    #
    # ## Features
    #
    # * Supports using `;`, `|`, `&`, and `\n` escape characters.
    # * Supports escaping single and double-quoted strings.
    # * Supports using `;`, `#`, and `\n` terminator characters.
    #
    # @since 0.2.0
    #
    class CommandInjection < WebVuln

      # The character to use to escape a quoted string.
      #
      # @return [String, nil]
      attr_reader :escape_quote

      # The escape character or string to use to escape the command and execute
      # another.
      #
      # @return [String]
      attr_reader :escape_operator

      # The terminator charactor to terminate the injected command with.
      #
      # @return [String, nil]
      attr_reader :terminator

      #
      # Initializes the command injection vulnerability.
      #
      # @param [URI::HTTP, String] url
      #   The URL to test or exploit.
      #
      # @param [String, nil] escape_quote
      #   The optional character to use to escape a quoted string.
      #
      # @param [String] escape_operator
      #   The escape character or string to use to escape the command
      #   and execute another.
      #
      # @param [String, nil] terminator
      #   The optional terminator character to terminate the injected command
      #   with.
      #
      def initialize(url, escape_quote:    nil,
                          escape_operator: nil,
                          terminator:      nil,
                          **kwargs)
        super(url,**kwargs)

        @escape_quote    = escape_quote
        @escape_operator = escape_operator
        @terminator      = terminator

        @escape_string = build_escape_string
      end

      private

      #
      # Builds the command escape String.
      #
      # @return [String, nil]
      #
      def build_escape_string
        if @escape_quote || @escape_operator
          "#{original_value}#{@escape_quote}#{@escape_operator}"
        end
      end

      public

      #
      # Scans the URL for command injections.
      #
      # Tests the URL and a specific query param, header name, cookie param, or
      # form param for Command Injection by enumerating over various Command
      # Injection escape syntaxes.
      #
      # @param [URI::HTTP] url
      #   The URL to test.
      #
      # @param [Array<String, nil>, String, nil] escape_quote
      #   The optional escape quote character(s) to test.
      #
      # @param [Array<String, nil>, String, nil] escape_operator
      #   The optional escape operator character(s) to test.
      #
      # @param [Array<String, nil>, String, nil] terminator
      #   The optional command termination character(s) to test.
      #
      # @param [Ronin::Support::Network::HTTP, nil] http
      #   An HTTP session to use for testing the URL.
      #
      # @param [Hash{Symbol => Object}] kwargs
      #   Additional keyword arguments for {#initialize}.
      #
      # @option kwargs [Symbol, String, true, nil] :query_param
      #   The query param name to test.
      #
      # @option kwargs [Symbol, String, nil] :header_name
      #   The header name to test.
      #
      # @option kwargs [Symbol, String, true, nil] :cookie_param
      #   The cookie param name to test.
      #
      # @option kwargs [Symbol, String, nil] :form_param
      #   The form param name to test.
      #
      # @return [CommandInjection, nil]
      #   The first discovered Command Injection vulnerability for the specific
      #   query param, header name, cookie param, or form param.
      #
      # @api private
      #
      # @since 0.2.0
      #
      def self.test_param(url, escape_quote:    [nil, "'", '"', '`'],
                               escape_operator: [';', '|', '&', "\n"],
                               terminator:      [nil, ';', '#', "\n"],
                               # keyword arguments for initialize
                               http: , **kwargs)
        Array(escape_quote).each do |escape_quote_char|
          Array(escape_operator).each do |escape_operator_char|
            Array(terminator).each do |terminator_char|
              vuln = new(url, escape_quote:    escape_quote_char,
                              escape_operator: escape_operator_char,
                              terminator:      terminator_char,
                              http:            http,
                              **kwargs)

              return vuln if vuln.vulnerable?
            end
          end
        end

        return nil
      end

      #
      # Escapes the given SQL and turns it into a SQL injection.
      #
      # @param [#to_s] command
      #   The command to escape.
      #
      # @return [String]
      #   The escaped SQL expression.
      #
      def escape(command)
        cmdi = "#{@escape_string}#{command}"

        if @terminator
          cmdi << @terminator
        elsif (@escape_quote && cmdi.end_with?(@escape_quote))
          cmdi.chop!
        end

        return cmdi
      end

      #
      # Encodes the command injection payload.
      #
      # @see #escape
      #
      def encode_payload(sql)
        escape(sql)
      end

      #
      # Tests whether the URL is vulnerable to command injection.
      #
      # @return [Boolean]
      #
      def vulnerable?
        test_command_output || test_sleep
      end

      # Regular expression to match the output of the `id` command.
      ID_OUTPUT_REGEX = /uid=\d+\([^\)]+\) gid=\d+\([^\)]+\) groups=\d+\([^\)]+\)/

      #
      # Tests whether the URL is vulnerable to command injection, by executing
      # the `id` command and the output is included in the response body.
      #
      # @return [Boolean]
      #
      # @api private
      #
      def test_command_output
        response = exploit('id')

        if response.body =~ ID_OUTPUT_REGEX
          return true
        end
      end

      #
      # Tests whether the URL is vulnerable to command injection, by calling the
      # sleep command to see if it takes longer for the response to be
      # returned.
      #
      # @return [Boolean]
      #
      # @api private
      #
      def test_sleep
        start_time = Time.now

        exploit("sleep 5")

        stop_time = Time.now
        delta     = (stop_time - start_time)

        # if the response took more than 5 seconds, our SQL sleep function
        # probably worked.
        return delta > 5.0
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
        :command_injection
      end

    end
  end
end
