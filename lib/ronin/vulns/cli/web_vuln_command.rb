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

                          self.headers[name] = value
                        end

        option :cookie, short: '-C',
                        value: {
                          type: String,
                          usage: 'COOKIE'
                        },
                        desc: 'Sets the raw Cookie header' do |cookie|
                          cookie = Support::Network::HTTP::Cookie.parse(cookie)

                          self.cookie.merge!(cookie)
                        end

        option :cookie_param, short: '-c',
                              value: {
                                type:  /[^\s=]+=\w+/,
                                usage: 'NAME=VALUE'
                              },
                              desc: 'Sets an additional cookie param' do |param|
                                name, value = param.split('=',2)

                                self.cookie[name] = value
                              end

        option :referer, short: '-R',
                         value: {
                           type: String,
                           usage: 'URL'
                         },
                         desc: 'Sets the Referer header' do |referer|
                           self.referer = referer
                         end

        option :form_param, short: '-F',
                            value: {
                              type: /[^\s=]+=\w+/,
                              usage: 'NAME=VALUE'
                            },
                            desc: 'Sets an additional form param' do |param|
                              name, value = param.split('=',2)

                              self.form_data[name] = value
                            end

        option :test_query_param, value: {
                                    type: String,
                                    usage: 'NAME'
                                  },
                                  desc: 'Tests the URL query param name' do |name|
                                    case (test_query_params = self.test_query_params)
                                    when true
                                      # no-op, test all query params
                                    when Set
                                      test_query_params << name
                                    end
                                  end

        option :test_all_query_params, desc: 'Test all URL query param names' do
          self.test_query_params = true
        end

        option :test_header_name, value: {
                                    type: String,
                                    usage: 'NAME'
                                  },
                                  desc: 'Tests the HTTP Header name' do |name|
                                    self.test_header_names << name
                                  end

        option :test_cookie_param, value: {
                                     type: String,
                                     usage: 'NAME'
                                   },
                                   desc: 'Tests the HTTP Cookie name' do |name|
                                     case (test_cookie_params = self.test_cookie_params)
                                     when true
                                       # no-op, test all query params
                                     when Set
                                       test_cookie_params << name
                                     end
                                   end

        option :test_all_cookie_params, desc: 'Test all Cookie param names' do
          self.test_cookie_params = true
        end

        option :test_form_param, value: {
                                   type: String,
                                   usage: 'NAME'
                                 },
                                 desc: 'Tests the form param name' do |name|
                                   self.test_form_params << name
                                 end

        option :test_all_form_params, desc: 'Tests all form param names' do
          self.test_form_params = true
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

        # Keywrod arguments that will be used in {#scan_url} and {#test_url} to
        # call {WebVuln.scan} or {WebVuln.test}.
        #
        # @return [Hash{Symbol => Object}]
        attr_reader :scan_kwargs

        #
        # Initializes the command.
        #
        # @param [Hash{Symbol => Object}] kwargs
        #   Additional keyword arguments.
        #
        def initialize(**kwargs)
          super(**kwargs)

          @scan_mode   = :first
          @scan_kwargs = {}
        end

        #
        # Runs the command.
        #
        # @param [Array<String>] urls
        #   The URL(s) to scan.
        #
        def run(*urls)
          unless (options[:input] || !urls.empty?)
            print_error "must specify URL(s) or --input"
            exit(-1)
          end

          vulns_discovered = false

          if options[:input]
            File.open(options[:input]) do |file|
              file.each_line(chomp: true) do |url|
                vulns_discovered ||= process_url(url)
              end
            end
          elsif !urls.empty?
            urls.each do |url|
              vulns_discovered ||= process_url(url)
            end
          end

          unless vulns_discovered
            puts colors.green("No vulnerabilities found")
          end
        end

        #
        # Processes a URL.
        #
        # @param [String] url
        #   A URL to scan.
        #
        # @return [Boolean]
        #   Indicates whether a vulnerability was discovered in the URL.
        #
        def process_url(url)
          unless url.start_with?('http://') || url.start_with?('https://')
            print_error("URL must start with http:// or https://: #{url.inspect}")
            exit(-1)
          end

          vuln_discovered = false

          if @scan_mode == :first
            if (first_vuln = test_url(url))
              log_vuln(first_vuln)

              vuln_discovered = true
            end
          else
            scan_url(url) do |vuln|
              log_vuln(vuln)

              vuln_discovered = true
            end
          end

          return vuln_discovered
        end

        #
        # Additional headers.
        #
        # @return [Hash{String => String}]
        #
        def headers
          @scan_kwargs[:headers] ||= {}
        end

        #
        # The optional `Cookie` header to send.
        #
        # @return [Ronin::Support::Network::HTTP::Cookie]
        #
        def cookie
          @scan_kwargs[:cookie] ||= Support::Network::HTTP::Cookie.new
        end

        #
        # The optional HTTP `Referer` header to send.
        #
        # @return [String, nil]
        #
        def referer
          @scan_kwargs[:referer]
        end

        #
        # Sets the HTTP `Referer` header to send.
        #
        # @param [String, nil] new_referer
        #   The new `Referer` header to send.
        #
        # @return [String, nil]
        #
        def referer=(new_referer)
          @scan_kwargs[:referer] = new_referer
        end

        #
        # Additional form params.
        #
        # @return [Hash{String => String}, nil]
        #
        def form_data
          @scan_kwargs[:form_data] ||= {}
        end

        #
        # The URL query params to test.
        #
        # @return [Set<String>, true]
        #
        def test_query_params
          @scan_kwargs[:query_params] ||= Set.new
        end

        #
        # Sets the URL query params to test.
        #
        # @param [Set<String>, true] new_query_params
        #   The query params to test.
        #
        # @return [Set<String>, true]
        #
        def test_query_params=(new_query_params)
          @scan_kwargs[:query_params] = new_query_params
        end

        #
        # The HTTP Header names to test.
        #
        # @return [Set<String>]
        #
        def test_header_names
          @scan_kwargs[:header_names] ||= Set.new
        end

        #
        # The HTTP Cookie to test.
        #
        # @return [Set<String>, true]
        #
        def test_cookie_params
          @scan_kwargs[:cookie_params] ||= Set.new
        end

        #
        # Sets the HTTP Cookie to test.
        #
        # @param [Set<String>, true] new_cookie_params
        #   The new cookie param names to test.
        #
        # @return [Set<String>, true]
        #
        def test_cookie_params=(new_cookie_params)
          @scan_kwargs[:cookie_params] = new_cookie_params
        end

        #
        # The form params to test.
        #
        # @return [Set<String>, nil]
        #
        def test_form_params
          @scan_kwargs[:form_params] ||= Set.new
        end

        #
        # Sets the form params to test.
        #
        # @param [Set<String>, true] new_form_params
        #   The new form param names to test.
        #
        # @return [Set<String>, true]
        #
        def test_form_params=(new_form_params)
          @scan_kwargs[:form_params] = new_form_params
        end

        #
        # Scans a URL for web vulnerabilities.
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
        # Tests a URL for web vulnerabilities.
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
