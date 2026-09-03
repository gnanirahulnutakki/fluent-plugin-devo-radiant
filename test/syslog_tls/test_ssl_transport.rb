# frozen_string_literal: true

# Copyright 2016 Acquia, Inc.
# Copyright 2016-2019 t.e.morgan.
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
require 'fluent_plugin_devo_radiant/syslog_tls/ssl_transport'

class DevoRadiantSSLTransportTest < Test::Unit::TestCase
  SSLTransport = FluentPluginDevoRadiant::SyslogTls::SSLTransport

  class NoConnectTransport < SSLTransport
    def connect; end
  end

  class AlwaysFailingTransport < SSLTransport
    attr_reader :write_attempts

    def connect
      @socket = StringIO.new
    end

    def do_write(_data)
      @write_attempts = (@write_attempts || 0) + 1
      raise IOError, 'simulated socket failure'
    end
  end

  class MinimumVersionProbe
    attr_reader :value

    def min_version=(value)
      @value = value
    end
  end

  def test_default_context_verifies_peers_with_system_ca_paths
    transport = NoConnectTransport.new('logs.example.invalid', 443)
    context = transport.send(:build_ssl_context)

    assert_equal OpenSSL::SSL::VERIFY_PEER, context.verify_mode
    assert_true context.verify_hostname
    assert_not_nil context.cert_store
  end

  def test_ca_cert_false_explicitly_disables_peer_and_hostname_checks
    transport = NoConnectTransport.new('logs.example.invalid', 443, ca_cert: false)
    context = transport.send(:build_ssl_context)

    assert_equal OpenSSL::SSL::VERIFY_NONE, context.verify_mode
    assert_false context.verify_hostname
  end

  def test_minimum_tls_version_is_applied_without_pinning_a_maximum
    transport = NoConnectTransport.new('logs.example.invalid', 443, tls_min_version: :'TLSv1_2')
    probe = MinimumVersionProbe.new

    transport.send(:configure_tls_min_version, probe)

    assert_equal OpenSSL::SSL::TLS1_2_VERSION, probe.value
  end

  def test_invalid_minimum_tls_version_is_rejected
    assert_raise(ArgumentError) do
      NoConnectTransport.new('logs.example.invalid', 443, tls_min_version: :'TLSv1_1')
    end
  end

  def test_transport_exhausts_retries_then_raises
    transport = AlwaysFailingTransport.new('logs.example.invalid', 443, max_retries: 3)

    error = assert_raise(IOError) { transport.write('MESSAGE') }

    assert_equal 'simulated socket failure', error.message
    assert_equal 3, transport.write_attempts
  end
end
