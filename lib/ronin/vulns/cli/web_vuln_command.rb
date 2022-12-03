#
# ronin-vulns - A Ruby library for blind vulnerability testing.
#
# Copyright (c) 2007-2022 Hal Brodigan (postmodern.mod3 at gmail.com)
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

require 'ronin/vulns/cli/command'
require 'ronin/vulns/cli/logging'

require 'ronin/support/network/http/cookie'

require 'set'

module Ronin
  module Vulns
    class CLI
      #
      # Base class for all web vulnerability commands.
      #
      class WebVulnCommand < Command

        include Logging

        option :first, short: '-F',
                       desc:  'Only find the first vulnerability for each URL' do
                         @scan_mode = :first
                       end

        option :all, short: '-A',
                     desc: 'Find all vulnerabilities for each URL' do
                       @scan_mode = :all
                     end

        option :header, short: '-H',
                        value: {
                          type:  /[A-Za-z0-9-]+:\s*\w+/,
                          usage: '"Name: value"'
                        },
                        desc: 'Sets an additional header' do |header|
                          name, value = header.split(/:\s*/,2)

                          @headers ||= {}
                          @headers[name] = value
                        end

        option :cookie, short: '-C',
                        value: {
                          type: String,
                          usage: 'COOKIE'
                        },
                        desc: 'Sets the raw Cookie header' do |cookie|
                          @raw_cookie = cookie
                        end

        option :cookie_param, short: '-c',
                              value: {
                                type:  /[^\s=]+=\w+/,
                                usage: 'NAME=VALUE'
                              },
                              desc: 'Sets an additional cookie param' do |param|
                                name, value = param.split('=',2)

                                @cookie ||= Support::Network::HTTP::Cookie.new
                                @cookie[name] = value
                              end

        option :referer, short: '-R',
                         value: {
                           type: String,
                           usage: 'URL',
                         },
                         desc: 'Sets the Referer header' do |referer|
                           @referer = referer
                         end

        option :form_param, short: '-F',
                            value: {
                              type: /[^\s=]+=\w+/,
                              usage: 'NAME=VALUE'
                            },
                            desc: 'Sets an additional form param' do |param|
                              name, value = param.split('=',2)

                              @form_data ||= {}
                              @form_data[name] = value
                            end

        option :test_query_param, value: {
                                    type: String,
                                    usage: 'NAME'
                                  },
                                  desc: 'Tests the URL query param name' do |name|
                                    @test_query_params ||= Set.new
                                    @test_query_params << name
                                  end

        option :test_all_query_params, desc: 'Test all URL query param names' do
          @test_all_query_params = true
        end

        option :test_header_name, value: {
                                    type: String,
                                    usage: 'NAME'
                                  },
                                  desc: 'Tests the HTTP Header name' do |name|
                                    @test_header_names ||= Set.new
                                    @test_header_names << name
                                  end

        option :test_cookie_param, value: {
                                     type: String,
                                     usage: 'NAME'
                                   },
                                   desc: 'Tests the HTTP Cookie name' do |name|
                                     @test_cookie_params ||= Set.new
                                     @test_cookie_params << name
                                   end

        option :test_all_cookie_params, desc: 'Test all Cookie param names' do
          @test_all_cookie_params = true
        end

        option :test_form_param, value: {
                                     type: String,
                                     usage: 'NAME'
                                   },
                                   desc: 'Tests the form param name' do |name|
                                     @test_form_params ||= Set.new
                                     @test_form_params << name
                                   end

        option :input, short: '-i',
                       value: {
                         type:  String,
                         usage: 'FILE'
                       },
                       desc: 'Reads URLs from the list file'

        argument :url, required: false,
                       repeats:  true,
                       desc:     'The URL(s) to scan'

        # The scan mode.
        #
        # @return [:first, :all]
        #   * `:first` - Only find the first vulnerability for each URL.
        #   * `:all` - Find all vulnerabilities for each URL.
        attr_reader :scan_mode

        # Additional headers.
        #
        # @return [Hash{String => String}, nil]
        attr_reader :headers

        # The raw `Cookie` header to send.
        #
        # @return [String, nil]
        attr_reader :raw_cookie

        # The optional `Cookie` header to send.
        #
        # @return [Ronin::Support::Network::HTTP::Cookie, nil]
        attr_reader :cookie

        # The optional `Referer` header to send.
        #
        # @return [String, nil]
        attr_reader :referer

        # Additional form params.
        #
        # @return [Hash{String => String}, nil]
        attr_reader :form_data

        # The URL query params to test.
        #
        # @return [Set<String>, nil]
        attr_reader :test_query_params

        # Indiciates whether to test all of the query params of the URL.
        #
        # @return [Boolean, nil]
        attr_reader :test_all_query_params

        # The HTTP Header names to test.
        #
        # @return [Set<String>, nil]
        attr_reader :test_header_names

        # The HTTP Cookie to test.
        #
        # @return [Set<String>, nil]
        attr_reader :test_cookie_params

        # Indiciates whether to test all `Cookie` params for the URL.
        #
        # @return [Boolean, nil]
        attr_reader :test_all_cookie_params

        # The form params to test.
        #
        # @return [Set<String>, nil]
        attr_reader :test_form_params

        #
        # Initializes the command.
        #
        # @param [Hash{Symbol => Object}] kwargs
        #   Additional keyword arguments.
        #
        def initialize(**kwargs)
          super(**kwargs)

          @scan_mode = :first
        end

        #
        # Runs the command.
        #
        # @param [Array<String>] urls
        #   The URL(s) to scan.
        #
        def run(*urls)
          if options[:input]
            File.open(options[:input]) do |file|
              file.each_line(chomp: true) do |url|
                process_url(url)
              end
            end
          elsif !urls.empty?
            urls.each do |url|
              process_url(url)
            end
          else
            print_error "must specify URL(s) or --input"
            exit(-1)
          end
        end

        #
        # Prcesses a URL.
        #
        # @param [String] url
        #   A URL to scan.
        #
        def process_url(url)
          if @scan_mode == :first
            if (first_vuln = test_url(url))
              print_vuln(first_vuln)
            end
          else
            scan_url(url) do |vuln|
              print_vuln(vuln)
            end
          end
        end

        #
        # The keyword arguments for {WebVuln.scan}.
        #
        # @return [Hash{String => String}]
        #   The keyword arguments.
        #
        def scan_kwargs
          kwargs = {}

          kwargs[:headers] = @headers if @headers

          if @raw_cookie
            kwargs[:cookie] = @raw_cookie
          elsif @cookie
            kwargs[:cookie] = @cookie
          end

          kwargs[:referer]   = @referer   if @referer
          kwargs[:form_data] = @form_data if @form_data

          if @test_query_params
            kwargs[:query_params]  = @test_query_params
          elsif @test_all_query_params
            kwargs[:query_params]  = true
          end

          kwargs[:header_names]  = @test_header_names  if @test_header_names

          if @test_cookie_params
            kwargs[:cookie_params] = @test_cookie_params
          elsif @test_all_cookie_params
            kwargs[:cookie_params] = true
          end

          kwargs[:form_params]   = @test_form_params   if @test_form_params

          return kwargs
        end

        #
        # Scans a URL for web vulnerabiltiies.
        #
        # @param [String] url
        #   The URL to scan.
        #
        # @yield [vuln]
        #   The given block will be passed each discovered web vulnerability.
        #
        # @yieldparam [WebVuln] vuln
        #   A web vulnerability discovered on the URL.
        #
        # @abstract
        #
        def scan_url(url,&block)
          raise(NotImplementedError,"#{self.class}#scan_url was not defined")
        end

        #
        # Tests a URL for web vulnerabiltiies.
        #
        # @param [String] url
        #   The URL to test.
        #
        # @return [WebVuln, nil] vuln
        #   The first web vulnerability discovered on the URL.
        #
        # @abstract
        #
        def test_url(url)
          raise(NotImplementedError,"#{self.class}#test_url was not defined")
        end

      end
    end
  end
end
