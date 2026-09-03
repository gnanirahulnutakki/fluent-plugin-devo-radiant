# frozen_string_literal: true

# Copyright 2016 Acquia, Inc.
# Copyright 2016 t.e.morgan.
# Copyright 2021 Devo .Inc.
# Copyright 2026 Radiant Logic, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'stringio'
require 'helper'
require 'fluent_plugin_devo_radiant/syslog_tls/logger'

class DevoRadiantSyslogNamespaceAndLoggerTest < Test::Unit::TestCase
  SyslogTls = FluentPluginDevoRadiant::SyslogTls

  def test_vendored_constants_are_fork_namespaced
    assert_not_nil defined?(FluentPluginDevoRadiant::SyslogTls::Logger)
    assert_not_nil defined?(FluentPluginDevoRadiant::SyslogTls::SSLTransport)
    assert_false Object.const_defined?(:SyslogTls, false)
  end

  def test_logger_preserves_upstream_syslog_message_shape
    output = StringIO.new
    logger = SyslogTls::Logger.new(output, 'TOKEN')
    logger.hostname('hostname')
    logger.app_name('appname')
    logger.facility('SYSLOG')
    time = Time.at(1_725_000_000)

    logger.log(:WARN, 'MESSAGE', time: time)

    timestamp = time.to_datetime.strftime('%b %d %H:%M:%S')
    assert_equal "<44>#{timestamp} hostname appname MESSAGE\n", output.string
  end

  def test_protocol_rejects_unknown_severity_and_facility
    header = SyslogTls::Header.new

    assert_raise(ArgumentError) { header.severity = 'NOT_A_SEVERITY' }
    assert_raise(ArgumentError) { header.facility = 'NOT_A_FACILITY' }
  end
end
