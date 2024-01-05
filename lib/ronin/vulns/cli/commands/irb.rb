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
require 'ronin/vulns/cli/ruby_shell'

module Ronin
  module Vulns
    class CLI
      module Commands
        #
        # Starts an interactive Ruby shell with `ronin-vulns` loaded.
        #
        # ## Usage
        #
        #     ronin-vulns irb [options]
        #
        # ## Options
        #
        #     -h, --help                       Print help information
        #
        # @since 0.2.0
        #
        class Irb < Command

          description "Starts an interactive Ruby shell with ronin-vulns loaded"

          man_page 'ronin-vulns-irb.1'

          #
          # Runs the `ronin-vulns irb` command.
          #
          def run
            require 'ronin/vulns'
            CLI::RubyShell.start
          end

        end
      end
    end
  end
end
