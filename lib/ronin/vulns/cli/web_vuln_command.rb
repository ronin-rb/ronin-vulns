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

require 'ronin/vulns/cli/command'
require 'ronin/vulns/cli/importable'
require 'ronin/vulns/cli/printing'

require 'ronin/support/network/http/cookie'
require 'ronin/support/network/http/user_agents'
require 'command_kit/printing/indent'

require 'set'

module Ronin
  module Vulns
    class CLI
      #
      # Base class for all web vulnerability commands.
      #
      class WebVulnCommand < Command

        include CommandKit::Printing::Indent
        include Printing
        include Importable

        option :import, desc: 'Imports discovered vulnerabilities into the database'
        option :first, short: '-F',
                       desc:  'Only find the first vulnerability for each URL' do
                         @scan_mode = :first
                       end

        option :all, short: '-A',
                     desc: 'Find all vulnerabilities for each URL' do
                       @scan_mode = :all
                     end

        option :print_curl, desc: 'Also prints an example curl command for each vulnerability'

        option :print_http, desc: 'Also prints an example HTTP request for each vulnerability'

        option :request_method, short: '-M',
                                value: {
                                  type: {
                                    'COPY'      => :copy,
                                    'DELETE'    => :delete,
                                    'GET'       => :get,
                                    'HEAD'      => :head,
                                    'LOCK'      => :lock,
                                    'MKCOL'     => :mkcol,
                                    'MOVE'      => :move,
                                    'OPTIONS'   => :options,
                                    'PATCH'     => :patch,
                                    'POST'      => :post,
                                    'PROPFIND'  => :propfind,
                                    'PROPPATCH' => :proppatch,
                                    'PUT'       => :put,
                                    'TRACE'     => :trace,
                                    'UNLOCK'    => :unlock
                                  }
                                },
                                desc: 'The HTTP request method to use' do |verb|
                                  self.request_method = verb
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

        option :user_agent_string, short: '-U',
                                   value: {
                                     type:  String,
                                     usage: 'STRING'
                                   },
                                   desc: 'Sets the User-Agent header' do |ua|
                                     self.user_agent = ua
                                   end

        option :user_agent, short: '-u',
                            value: {
                              type: Support::Network::HTTP::UserAgents::ALIASES.transform_keys { |key|
                                key.to_s.tr('_','-')
                              }
                            },
                            desc: 'Sets the User-Agent to use' do |name|
                              self.user_agent = name
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

          db_connect if options[:import]

          vulns = []

          if options[:input]
            File.open(options[:input]) do |file|
              file.each_line(chomp: true) do |url|
                process_url(url) do |vuln|
                  vulns << vuln
                end
              end
            end
          elsif !urls.empty?
            urls.each do |url|
              process_url(url) do |vuln|
                vulns << vuln
              end
            end
          end

          puts unless vulns.empty?
          print_vulns(vulns)
        end

        #
        # Print a summary of all web vulnerabilities found.
        #
        # @param [Array<WebVuln>] vulns
        #   The discovered web vulnerabilities.
        #
        # @param [Boolean] print_curl
        #   Prints an example `curl` command to trigger the web vulnerability.
        #
        # @param [Boolean] print_http
        #   Prints an example HTTP request to trigger the web vulnerability.
        #
        # @since 0.2.0
        #
        def print_vulns(vulns, print_curl: options[:print_curl],
                               print_http: options[:print_http])
          super(vulns, print_curl: print_curl,
                       print_http: print_http)
        end

        #
        # Prints detailed information about a discovered web vulnerability.
        #
        # @param [WebVuln] vuln
        #   The web vulnerability to log.
        #
        # @param [Boolean] print_curl
        #   Prints an example `curl` command to trigger the web vulnerability.
        #
        # @param [Boolean] print_http
        #   Prints an example HTTP request to trigger the web vulnerability.
        #
        # @since 0.2.0
        #
        def print_vuln(vuln, print_curl: options[:print_curl],
                             print_http: options[:print_http])
          super(vuln, print_curl: print_curl,
                      print_http: print_http)
        end

        #
        # Processes a URL.
        #
        # @param [String] url
        #   A URL to scan.
        #
        # @yield [vuln]
        #   The given block will be passed each newly discovered web
        #   vulnerability.
        #
        # @yieldparam [WebVuln] vuln
        #   A newly discovered web vulnerability.
        #
        def process_url(url)
          unless url.start_with?('http://') || url.start_with?('https://')
            print_error("URL must start with http:// or https://: #{url.inspect}")
            exit(-1)
          end

          if @scan_mode == :first
            if (first_vuln = test_url(url))
              process_vuln(first_vuln)
              yield first_vuln
            end
          else
            scan_url(url) do |vuln|
              process_vuln(vuln)
              yield vuln
            end
          end
        end

        #
        # Logs and optioanlly imports a new discovered web vulnerability.
        #
        # @param [WebVuln] vuln
        #   The discovered web vulnerability.
        #
        # @since 0.2.0
        #
        def process_vuln(vuln)
          log_vuln(vuln)
          import_vuln(vuln) if options[:import]
        end

        #
        # The HTTP request method to use.
        #
        # @return [:copy, :delete, :get, :head, :lock, :mkcol, :move,
        #          :options, :patch, :post, :propfind, :proppatch, :put,
        #          :trace, :unlock]
        #
        # @since 0.2.0
        #
        def request_method
          @scan_kwargs[:request_method]
        end

        #
        # Sets the HTTP request method to use.
        #
        # @param [:copy, :delete, :get, :head, :lock, :mkcol, :move,
        #         :options, :patch, :post, :propfind, :proppatch, :put,
        #         :trace, :unlock] new_request_method
        #
        # @return [:copy, :delete, :get, :head, :lock, :mkcol, :move,
        #          :options, :patch, :post, :propfind, :proppatch, :put,
        #          :trace, :unlock]
        #
        # @since 0.2.0
        #
        def request_method=(new_request_method)
          @scan_kwargs[:request_method] = new_request_method
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
        # The optional HTTP `User-Agent` header to send.
        #
        # @return [String, :random, :chrome, :chrome_linux, :chrome_macos,
        #          :chrome_windows, :chrome_iphone, :chrome_ipad,
        #          :chrome_android, :firefox, :firefox_linux, :firefox_macos,
        #          :firefox_windows, :firefox_iphone, :firefox_ipad,
        #          :firefox_android, :safari, :safari_macos, :safari_iphone,
        #          :safari_ipad, :edge, :linux, :macos, :windows, :iphone,
        #          :ipad, :android, nil]
        #
        # @since 0.2.0
        #
        def user_agent
          @scan_kwargs[:user_agent]
        end

        #
        # Sets the HTTP `User-Agent` header.
        #
        # @param [String, :random, :chrome, :chrome_linux, :chrome_macos,
        #         :chrome_windows, :chrome_iphone, :chrome_ipad,
        #         :chrome_android, :firefox, :firefox_linux, :firefox_macos,
        #         :firefox_windows, :firefox_iphone, :firefox_ipad,
        #         :firefox_android, :safari, :safari_macos, :safari_iphone,
        #         :safari_ipad, :edge, :linux, :macos, :windows, :iphone,
        #         :ipad, :android] new_user_agent
        #   The new `User-Agent` value to send.
        #
        # @return [String, :random, :chrome, :chrome_linux, :chrome_macos,
        #          :chrome_windows, :chrome_iphone, :chrome_ipad,
        #          :chrome_android, :firefox, :firefox_linux, :firefox_macos,
        #          :firefox_windows, :firefox_iphone, :firefox_ipad,
        #          :firefox_android, :safari, :safari_macos, :safari_iphone,
        #          :safari_ipad, :edge, :linux, :macos, :windows, :iphone,
        #          :ipad, :android]
        #
        # @since 0.2.0
        #
        def user_agent=(new_user_agent)
          @scan_kwargs[:user_agent] = new_user_agent
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
