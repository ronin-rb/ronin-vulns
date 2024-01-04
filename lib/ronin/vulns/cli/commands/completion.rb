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

require 'ronin/vulns/root'
require 'ronin/core/cli/completion_command'

module Ronin
  module Vulns
    class CLI
      module Commands
        #
        # Manages the shell completion rules for `ronin-vulns`.
        #
        # ## Usage
        #
        #     ronin-vulns completion [options]
        #
        # ## Options
        #
        #         --print                      Prints the shell completion file
        #         --install                    Installs the shell completion file
        #         --uninstall                  Uninstalls the shell completion file
        #     -h, --help                       Print help information
        #
        # ## Examples
        #
        #     ronin-vulns completion --print
        #     ronin-vulns completion --install
        #     ronin-vulns completion --uninstall
        #
        # @since 0.2.0
        #
        class Completion < Core::CLI::CompletionCommand

          completion_file File.join(ROOT,'data','completions','ronin-vulns')

          man_dir File.join(ROOT,'man')
          man_page 'ronin-vulns-completion.1'

          description 'Manages the shell completion rules for ronin-vulns'

        end
      end
    end
  end
end
