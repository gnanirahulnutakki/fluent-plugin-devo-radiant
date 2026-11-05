# frozen_string_literal: true

require_relative 'lib/fluent/plugin/devo_radiant_constants'

Gem::Specification.new do |gem|
  gem.name = 'fluent-plugin-devo-radiant'
  gem.version = Fluent::Plugin::DevoRadiantConstants::VERSION
  gem.authors = ['Radiant Logic, Inc.']
  gem.email = ['support@radiantlogic.com']
  gem.summary = 'Hardened Fluentd TLS output plugin for Devo'
  gem.description = 'A production-hardened fork of fluent-plugin-devo 1.2.0 with buffered retry semantics, ' \
                    'credential masking, multi-worker support, configurable minimum TLS versions, and a ' \
                    'collision-free vendored syslog TLS namespace.'
  gem.homepage = 'https://github.com/gnanirahulnutakki/fluent-plugin-devo-radiant'
  gem.licenses = ['Apache-2.0']

  gem.metadata = {
    'bug_tracker_uri' => 'https://github.com/gnanirahulnutakki/fluent-plugin-devo-radiant/issues',
    'source_code_uri' => 'https://github.com/gnanirahulnutakki/fluent-plugin-devo-radiant',
    'rubygems_mfa_required' => 'true'
  }

  gem.files = Dir['lib/**/*.rb', 'LICENSE', 'NOTICE', 'README.md', 'CHANGELOG.md']
  gem.require_paths = ['lib']
  gem.required_ruby_version = '>= 3.1.0'

  gem.add_runtime_dependency 'fluentd', ['>= 1.16', '< 2']
  gem.add_development_dependency 'bundler', ['>= 2', '< 3']
  gem.add_development_dependency 'rake', '~> 13.0'
  gem.add_development_dependency 'test-unit', '~> 3.6'
end
