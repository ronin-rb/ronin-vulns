source 'https://rubygems.org'

gemspec

platform :jruby do
  gem 'jruby-openssl',	'~> 0.7'
end

# gem 'command_kit', '~> 0.4', github: 'postmodern/command_kit.rb',
#                              branch: '0.4.0'

# Ronin dependencies
gem 'ronin-support',	'~> 1.0', github: "ronin-rb/ronin-support",
                                branch: '1.0.0'
gem 'ronin-core',     '~> 0.1', github: "ronin-rb/ronin-core",
                                branch: 'main'

group :development do
  gem 'rake'
  gem 'rubygems-tasks',  '~> 0.2'

  gem 'rspec',           '~> 3.0'
  gem 'webmock',         '~> 3.0'
  gem 'simplecov',       '~> 0.20'

  gem 'kramdown',        '~> 2.0'
  gem 'kramdown-man',    '~> 0.1'

  gem 'redcarpet',       platform: :mri
  gem 'yard',            '~> 0.9'
  gem 'yard-spellcheck', require: false

  gem 'dead_end',        require: false
  gem 'sord',            require: false, platform: :mri
  gem 'stackprof',       require: false, platform: :mri
end
