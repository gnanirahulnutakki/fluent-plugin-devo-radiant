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

require 'json'
require 'helper'
require 'fluent/msgpack_factory'
require 'fluent/test/driver/output'
require 'fluent/plugin/out_devo_radiant'

class DevoRadiantOutputTest < Test::Unit::TestCase
  ChunkMetadata = Struct.new(:tag)

  class TestChunk
    attr_reader :metadata

    def initialize(tag, events)
      @metadata = ChunkMetadata.new(tag)
      @events = events
    end

    def msgpack_each(&block)
      @events.each(&block)
    end
  end

  class RaisingTransport
    attr_reader :attempts

    def initialize
      @attempts = 0
    end

    def write(_message)
      @attempts += 1
      raise IOError, 'stubbed transport failure'
    end

    def closed?
      false
    end

    def close; end
  end

  class CapturingLogger
    Header = Struct.new(:severity, :facility, :hostname, :app_name, :procid, :msgid)
    Entry = Struct.new(:severity, :message, :time, :header)

    attr_reader :entries

    def initialize
      @closed = false
      @entries = []
    end

    def log(severity, message, time:)
      header = Header.new
      yield header if block_given?
      @entries << Entry.new(severity, message, time, header)
    end

    def closed?
      @closed
    end

    def close
      @closed = true
    end
  end

  def setup
    Fluent::Test.setup
  end

  def create_driver(extra_config = '')
    Fluent::Test::Driver::Output.new(Fluent::Plugin::DevoRadiantOutput).configure(<<~CONFIG)
      host logs.example.invalid
      port 443
      #{extra_config}
    CONFIG
  end

  def test_secret_config_values_are_masked
    raw_token = 'raw-token-must-not-appear'
    raw_client_key = '/tmp/raw-client-private-key-must-not-appear.pem'
    driver = create_driver(<<~CONFIG)
      token #{raw_token}
      client_key #{raw_client_key}
    CONFIG

    dumped_config = driver.instance.config.to_s

    assert_not_include dumped_config, raw_token
    assert_not_include dumped_config, raw_client_key
    assert_include dumped_config, 'token xxxxxx'
    assert_include dumped_config, 'client_key xxxxxx'
  end

  def test_write_propagates_a_transport_failure
    driver = create_driver('token test-token')
    transport = RaisingTransport.new
    syslog_logger = FluentPluginDevoRadiant::SyslogTls::Logger.new(transport, 'test-token')
    driver.instance.define_singleton_method(:logger) { |_tag| syslog_logger }
    chunk = TestChunk.new('retry.tag', [[1_725_000_000, { 'message' => 'must retry' }]])

    error = assert_raise(IOError) { driver.instance.write(chunk) }

    assert_equal 'stubbed transport failure', error.message
    assert_equal 1, transport.attempts
  end

  def test_process_compatibility_path_also_propagates_a_transport_failure
    driver = create_driver('token test-token')
    transport = RaisingTransport.new
    syslog_logger = FluentPluginDevoRadiant::SyslogTls::Logger.new(transport, 'test-token')
    driver.instance.define_singleton_method(:logger) { |_tag| syslog_logger }

    assert_raise(IOError) do
      driver.instance.process('retry.tag', [[1_725_000_000, { 'message' => 'must fail' }]])
    end
  end

  def test_registered_under_both_type_names
    %w[devo_radiant devo].each do |type|
      assert_instance_of Fluent::Plugin::DevoRadiantOutput, Fluent::Plugin.new_output(type),
                         "@type #{type} should resolve to this plugin"
    end
  end

  def test_vendor_compatible_loader_resolves_devo
    assert_nothing_raised { require 'fluent/plugin/out_devo' }
    assert_instance_of Fluent::Plugin::DevoRadiantOutput, Fluent::Plugin.new_output('devo')
  end

  def test_multi_worker_and_buffer_capabilities
    instance = create_driver.instance

    assert_true instance.multi_workers_ready?
    assert_true instance.prefer_buffered_processing
    assert_true instance.formatted_to_msgpack_binary?
    assert_equal ['tag'], instance.buffer_config.chunk_keys
  end

  def test_logger_cache_is_scoped_by_worker_and_tag
    instance = create_driver.instance
    worker_id = 0
    created_loggers = []
    instance.define_singleton_method(:fluentd_worker_id) { worker_id }
    instance.define_singleton_method(:new_logger) do |_tag|
      CapturingLogger.new.tap { |new_logger| created_loggers << new_logger }
    end

    worker_zero_logger = instance.logger('same.tag')
    assert_same worker_zero_logger, instance.logger('same.tag')

    worker_id = 1
    worker_one_logger = instance.logger('same.tag')
    assert_not_same worker_zero_logger, worker_one_logger
    assert_equal 2, created_loggers.length
    assert_equal [[0, 'same.tag'], [1, 'same.tag']], instance.instance_variable_get(:@loggers).keys
  end

  def test_buffered_write_preserves_formatter_and_header_mappings
    driver = create_driver(<<~CONFIG)
      severity_key severity
      hostname_key source_host
      app_name_key application
      <format>
        @type single_value
        message_key message
      </format>
    CONFIG
    capturing_logger = CapturingLogger.new
    driver.instance.define_singleton_method(:logger) { |_tag| capturing_logger }
    chunk = TestChunk.new('mapped.tag', [[
      1_725_000_000,
      {
        'severity' => 'PANIC',
        'source_host' => 'record-host',
        'application' => 'record-app',
        'message' => 'mapped message'
      }
    ]])

    driver.instance.write(chunk)

    sent_entry = capturing_logger.entries.fetch(0)
    assert_equal 'EMERG', sent_entry.severity
    assert_equal 'record-host', sent_entry.header.hostname
    assert_equal 'recordapp', sent_entry.header.app_name
    assert_equal "mapped message", sent_entry.message
  end

  def test_buffered_format_and_write_preserve_tag_and_injected_record
    driver = create_driver(<<~CONFIG)
      token test-token
      <inject>
        tag_key source_tag
      </inject>
      <format>
        @type json
      </format>
      <buffer tag>
        @type memory
        flush_mode immediate
        flush_at_shutdown true
      </buffer>
    CONFIG
    capturing_logger = CapturingLogger.new
    created_for_tags = []
    driver.instance.define_singleton_method(:new_logger) do |tag|
      created_for_tags << tag
      capturing_logger
    end

    tag = 'app.production'
    time = Fluent::EventTime.new(1_725_000_000, 123_456_789)
    driver.run(default_tag: tag) do
      driver.feed(time, { 'message' => 'buffered record' })
    end

    assert_equal 1, driver.formatted.length
    unpacker = Fluent::MessagePackFactory.msgpack_unpacker
    unpacker.feed(driver.formatted.first)
    formatted_time, formatted_record = unpacker.read
    assert_equal time.to_i, formatted_time.to_i
    assert_equal 'buffered record', formatted_record['message']
    assert_equal tag, formatted_record['source_tag']

    assert_equal [tag], created_for_tags
    assert_equal 1, capturing_logger.entries.length
    sent_entry = capturing_logger.entries.first
    assert_equal 'INFO', sent_entry.severity
    assert_equal Time.at(time.sec, time.nsec, :nanosecond), sent_entry.time
    assert_equal({ 'message' => 'buffered record', 'source_tag' => tag, '@timestamp' => '2024-08-30T06:40:00.123Z' }, JSON.parse(sent_entry.message))
  end

  def test_tls_verification_disablement_is_warned
    peer_driver = create_driver('ca_cert false')
    hostname_driver = create_driver('verify_cert_name false')

    assert_include peer_driver.logs.join, 'TLS peer and hostname verification are disabled'
    assert_include hostname_driver.logs.join, 'TLS hostname verification is disabled'
  end

  def test_tls_minimum_version_defaults_to_1_2_and_accepts_1_3
    assert_equal :'TLSv1_2', create_driver.instance.tls_min_version

    if Fluent::Plugin::DevoRadiantOutput::TLS_MIN_VERSIONS.include?(:'TLSv1_3')
      assert_equal :'TLSv1_3', create_driver('tls_min_version TLSv1_3').instance.tls_min_version
    end
  end
end
