# frozen_string_literal: true

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

require 'helper'
require 'json'
require 'timeout'
require 'fluent/test/driver/output'
require 'fluent/plugin/out_devo_radiant'
require 'tls_server'

class DevoRecordRegressionTest < Test::Unit::TestCase
  Metadata = Struct.new(:tag)
  class Chunk
    attr_reader :metadata

    def initialize(plugin, rows, tag)
      @metadata = Metadata.new(tag)
      @bytes = rows.map { |time, record| plugin.format(tag, time, record) }.join
    end

    def msgpack_each(&block)
      unpacker = Fluent::MessagePackFactory.msgpack_unpacker
      unpacker.feed(@bytes)
      unpacker.each(&block)
    end
  end

  def setup
    Fluent::Test.setup
    @servers, @drivers, @threads = [], [], []
  end

  def teardown
    @threads.each { |thread| thread.kill if thread.alive?; thread.join }
    @drivers.each { |driver| driver.instance.send(:close_loggers) }
    @servers.reverse_each(&:stop)
  end

  def server(**options, &block)
    DevoTLSServer.new(**options, &block).tap { |peer| @servers << peer }
  end

  def driver(peer, extra = '')
    d = Fluent::Test::Driver::Output.new(Fluent::Plugin::DevoRadiantOutput, opts: { root_dir: peer.directory }).configure(<<~CONFIG)
      host 127.0.0.1
      port #{peer.port}
      ca_cert #{peer.cert_path}
      hostname fid-0
      app_name_key devo_tag
      #{extra}
    CONFIG
    @drivers << d
    factory = d.instance.method(:new_transport)
    d.instance.define_singleton_method(:new_transport) { factory.call(peer.transport_type) }
    d
  end

  def write(d, *records, tag: 'my.app.fid', time: Fluent::EventTime.new(1_793_917_801, 123_456_789))
    d.instance.write(Chunk.new(d.instance, records.map { |record| [time, record] }, tag))
  end

  def lines(peer, count)
    peer.await { peer.bytes.lines.length >= count }
    peer.bytes.lines
  end

  def payload(line)
    JSON.parse(line[line.index('{')..])
  end

  def priorities(peer, count)
    lines(peer, count).map { |line| line[/\A<(\d+)>/, 1].to_i - 128 }
  end

  def test_d01_detection_order_level_keys_and_opt_out
    peer = server
    d = driver(peer, 'severity_key chosen')
    rows = [
      { 'chosen' => 'DEBUG', 'LEVEL' => 'ERROR' },
      { 'chosen' => nil, 'LoGlEvEl' => 'Warning', 'message' => '2026-10-14T17:29:48,246 ERROR failure' },
      { 'message' => '2026-10-14T17:29:48,246 ERROR failure', 'RESULTCODE' => 0 },
      { 'log' => '[2026-10-14 17:29:48.246Z] [worker] FATAL failed' },
      { 'message' => 'not a dated ERROR prefix', 'RESULTCODE' => '80' },
      { 'message' => 'ordinary message' }
    ]
    write(d, *rows)
    assert_equal [7, 4, 3, 2, 3, 6], priorities(peer, rows.length)

    other = server
    no_mapping = driver(other)
    keys = Fluent::Plugin::DevoRadiantOutput::LEVEL_KEYS
    write(no_mapping, *keys.map { |key| { key.upcase => 'Error' } })
    assert_equal [3] * keys.length, priorities(other, keys.length)

    disabled = server
    off = driver(disabled, "auto_severity false\nseverity_key chosen")
    write(off, { 'level' => 'ERROR', 'RESULTCODE' => 80 }, { 'chosen' => 'FATAL' })
    assert_equal [6, 2], priorities(disabled, 2)
  end

  def test_d01_ldap_resultcode_matrix
    peer = server
    d = driver(peer)
    info = [0, 5, 6, 10, 14]
    errors = [1, 51, 52, 53, 54, 80]
    warnings = [2, 49, 99, -1]
    invalid = [nil, false, 'bad', '1.5', 1.5, {}, []]
    values = info + errors + warnings + invalid + [' 80 ', '10', '49']
    write(d, *values.map { |code| { 'RESULTCODE' => code } })
    assert_equal [6] * info.length + [3] * errors.length + [4] * warnings.length + [6] * invalid.length + [3, 6, 4], priorities(peer, values.length)
  end

  def test_d02_severity_matrix_never_poison_chunk
    peer = server
    d = driver(peer, 'severity_key level')
    aliases = {
      'FATAL' => 2, 'CRITICAL' => 2, 'SEVERE' => 3, 'Error' => 3,
      'warning' => 4, 'TRACE' => 7, 'FINE' => 7, 'FINER' => 7,
      'FINEST' => 7, 'VERBOSE' => 7, 'INFORMATION' => 6,
      'INFORMATIONAL' => 6, 'EMERGENCY' => 0, 'PANIC' => 0,
      'NONE' => 6, 'unknown' => 6, '' => 6, false => 6, 99 => 6,
      [] => 6, {} => 6, 3.0 => 3, 3.5 => 6
    }
    (0..7).each { |n| aliases[n] = n; aliases[n.to_s] = n }
    write(d, { 'message' => 'before' }, *aliases.map { |value, _| { 'level' => value } }, { 'message' => 'after' })
    assert_equal [6] + aliases.values + [6], priorities(peer, aliases.length + 2)
    assert_equal 'after', payload(peer.bytes.lines.last)['message']
  end

  def test_d02_d03_real_fluentd_flush_delivers_whole_chunk_once
    %w[oj json].each do |parser|
      peer = server
      d = driver(peer, <<~CONF)
        severity_key level
        <format>
          @type json
          json_parser #{parser}
        </format>
        <buffer tag>
          @type file
          path #{peer.directory}/buffer
          flush_mode immediate
          flush_thread_interval 0.01
          retry_type periodic
          retry_wait 0.05
          retry_randomize false
        </buffer>
      CONF
      d.run(default_tag: 'my.app.fid') do
        d.feed(1_793_917_801, { 'message' => 'before' })
        d.feed(1_793_917_801, { 'level' => 'FATAL', 'message' => "bad\xFF".b })
        d.feed(1_793_917_801, { 'message' => 'after' })
      end
      assert_equal %W[before bad\uFFFD after], lines(peer, 3).map { |line| payload(line)['message'] }
      assert_empty Dir[File.join(peer.directory, 'backup/**/*.log')]
      assert_not_include d.logs.join, 'failed to flush'
      assert_not_include d.logs.join, 'unrecoverable error'
    end
  end

  def test_d03_recursive_utf8_keys_values_and_headers_with_both_json_engines
    %w[oj json].each do |parser|
      peer = server
      d = driver(peer, <<~CONF)
        hostname_key source
        sanitize_tag false
        <format>
          @type json
          json_parser #{parser}
        </format>
      CONF
      record = {
        "key\xFF".b => ["bad\xFE".b, { "nested\xFF".b => 'Copyright ©'.b }],
        'source' => "host\xFF\r\n bad".b, 'devo_tag' => "my.app\xFF\n bad".b,
        'other' => 'café'.encode('ISO-8859-1')
      }
      write(d, record)
      line = lines(peer, 1).first.force_encoding('UTF-8')
      assert_true line.valid_encoding?
      assert_equal ["bad\uFFFD", { "nested\uFFFD" => 'Copyright ©' }], payload(line)["key\uFFFD"]
      assert_equal 'café', payload(line)['other']
      assert_include line, " host\uFFFDbad my.app\uFFFDbad "
      assert_equal 1, line.count("\n")
      assert_equal "host\xFF\r\n bad".b, record['source'], 'caller record must not be mutated'
    end
  end

  def test_d04_d05_one_line_per_event_for_all_builtin_formats
    %w[json single_value out_file ltsv csv tsv].each do |format|
      peer = server
      fields = %w[csv tsv].include?(format) ? "fields message\nkeys message" : ''
      d = driver(peer, "<format>\n@type #{format}\n#{fields}\n</format>")
      text = "exception\r\n\tat Frame\rCaused by:\nend\r\n\n"
      write(d, { 'message' => text }, { 'message' => 'second' })
      output = lines(peer, 2)
      assert_equal 2, output.length, format
      assert_true output.all? { |line| line.start_with?('<134>') && line.end_with?("\n") && !line.end_with?("\n\n") }, format
      assert_not_include output.join, "\r", format
      if format == 'json'
        assert_equal text, payload(output.first)['message'], 'JSON escaping must preserve original message'
      else
        assert_include output.first, '\n', format
      end
    end
  end

  def test_d07_timestamp_milliseconds_preserves_existing_and_header_shape
    peer = server
    d = driver(peer)
    time = Fluent::EventTime.new(Time.utc(2026, 11, 5, 22, 30, 1).to_i, 123_456_789)
    write(d, { 'message' => 'first' }, { '@timestamp' => 'existing' }, { '@timestamp' => nil }, time: time)
    output = lines(peer, 3)
    assert_equal '2026-11-05T22:30:01.123Z', payload(output[0])['@timestamp']
    assert_equal 'existing', payload(output[1])['@timestamp']
    assert_nil payload(output[2])['@timestamp']
    assert_match(/\A<134>#{Regexp.escape(Time.at(time.sec).strftime('%b %d %H:%M:%S'))} fid-0 my.app.fid /, output[0])

    other = server
    custom = driver(other, 'timestamp_key event_time')
    write(custom, { 'message' => 'custom' }, time: time.sec)
    assert_equal '2026-11-05T22:30:01.000Z', payload(lines(other, 1).first)['event_time']
    disabled = server
    off = driver(disabled, 'inject_timestamp false')
    write(off, { 'message' => 'off' })
    assert_false payload(lines(disabled, 1).first).key?('@timestamp')
  end

  def test_d07_process_path_injects_timestamp
    peer = server
    d = driver(peer)
    d.instance.process('my.app.fid', [[1_793_917_801.125, { 'message' => 'process' }]])
    assert_equal Time.at(1_793_917_801.125).utc.iso8601(3), payload(lines(peer, 1).first)['@timestamp']
  end

  def test_d08_sanitize_and_warn_once_per_distinct_original
    peer = server
    d = driver(peer, 'hostname_key source')
    tags = ['..my..app.vds_server_access/.', 'single_', 'a.b.c.d.e.f.g', 'a.' + 'x' * 49]
    2.times { tags.each { |tag| write(d, { 'devo_tag' => tag, 'source' => "bad host\r\n\t\u0000" }) } }
    output = lines(peer, tags.length * 2)
    assert_include output.first, ' badhost my.app.vdsserveraccess '
    assert_equal 2, d.logs.count { |entry| entry.include?('Devo tag changed:') }
    assert_equal 3, d.logs.count { |entry| entry.include?('Devo tag outside') }
    assert_equal 2, output.count { |line| line.include?(' single ') }, 'invalid tag still sent'
    assert_equal 2, output.count { |line| line.include?(' a.b.c.d.e.f.g ') }
    assert_equal 2, output.count { |line| line.include?(' a.' + 'x' * 49 + ' ') }
  end

  def test_d08_sanitize_false_still_removes_wire_delimiters
    peer = server
    d = driver(peer, "sanitize_tag false\nhostname_key source")
    write(d, { 'devo_tag' => "my.app_with/slash\r\n bad\t\u007F", 'source' => "host name\n\u0001" })
    assert_include lines(peer, 1).first, ' hostname my.app_with/slashbad '
  end

  def test_d20_ignored_configuration_warns_once_without_exposing_token
    peer = server
    d = driver(peer, "token private-placeholder\nprocid_key process\nmsgid_key id")
    write(d, { 'process' => 'proc-123', 'id' => 'msg-456' })
    output = lines(peer, 1).first
    assert_equal 1, d.logs.count { |entry| entry.include?('are ignored') }
    assert_not_include d.logs.join, 'private-placeholder'
    assert_not_include output, 'private-placeholder'
    assert_not_include output.split('{').first, 'proc-123'
    assert_not_include output.split('{').first, 'msg-456'
    assert_equal 'proc-123', payload(output)['process']
  end

  def test_d21_plain_tcp_same_framing_and_idle_reconnect
    peer = server(plain: true)
    d = driver(peer, "tls false\nidle_timeout 1")
    write(d, { 'message' => 'one' })
    lines(peer, 1)
    d.instance.logger('my.app.fid').transport.instance_variable_set(:@last_write, Time.now - 2)
    write(d, { 'message' => 'two' })
    assert_equal %w[one two], lines(peer, 2).map { |line| payload(line)['message'] }
    assert_equal 2, peer.connections
    assert_equal 1, d.logs.count { |entry| entry.include?('traffic is unencrypted') }
  end

  def test_d14_slow_new_connection_does_not_block_cached_tag
    handshakes = 0
    waiting, release, done = Queue.new, Queue.new, Queue.new
    peer = server(before_handshake: proc do |_socket|
      handshakes += 1
      if handshakes == 2
        waiting << true
        release.pop
      end
    end)
    d = driver(peer)
    write(d, { 'message' => 'initial' }, tag: 'my.cached')
    lines(peer, 1)
    creating = Thread.new { d.instance.logger('my.new') }
    @threads << creating
    Timeout.timeout(2) { waiting.pop }
    sending = Thread.new { write(d, { 'message' => 'cached' }, tag: 'my.cached'); done << true }
    @threads << sending
    assert_true Timeout.timeout(2) { done.pop }
    assert_equal %w[initial cached], lines(peer, 2).map { |line| payload(line)['message'] }
    release << true
    assert_not_nil creating.join(2)
    assert_not_nil sending.join(2)
  ensure
    release << true if release
  end

  def test_d14_concurrent_same_tag_publishes_one_logger_and_closes_loser
    peer = server
    d = driver(peer)
    ready, release, results = Queue.new, Queue.new, Queue.new
    original = d.instance.method(:new_logger)
    d.instance.define_singleton_method(:new_logger) do |tag|
      candidate = original.call(tag)
      ready << candidate
      release.pop
      candidate
    end
    2.times { @threads << Thread.new { results << d.instance.logger('my.same') } }
    candidates = 2.times.map { Timeout.timeout(3) { ready.pop } }
    2.times { release << true }
    @threads.each { |thread| assert_not_nil thread.join(2) }
    first, second = 2.times.map { results.pop }
    assert_same first, second
    assert_equal 1, candidates.count(&:closed?)
    assert_equal 1, d.instance.instance_variable_get(:@loggers).length
    assert_equal 1, peer.clients.count(&:closed?)
  ensure
    2.times { release << true } if release
  end

  def test_d15_shutdown_during_creation_closes_candidate_and_forbids_new_cache_entries
    peer = server
    d = driver(peer)
    ready, release, result = Queue.new, Queue.new, Queue.new
    original = d.instance.method(:new_logger)
    d.instance.define_singleton_method(:new_logger) do |tag|
      candidate = original.call(tag)
      ready << candidate
      release.pop
      candidate
    end
    creating = Thread.new do
      d.instance.logger('my.late')
    rescue IOError => error
      result << error
    end
    @threads << creating
    candidate = Timeout.timeout(3) { ready.pop }
    d.instance.shutdown
    release << true
    assert_not_nil creating.join(2)
    assert_kind_of IOError, result.pop
    assert_true candidate.closed?
    assert_empty d.instance.instance_variable_get(:@loggers)
    assert_raise(IOError) { d.instance.logger('my.later') }
    assert_true peer.clients.all?(&:closed?)
  ensure
    release << true if release
  end

  def test_d15_real_fluentd_inflight_flush_stays_closed_after_shutdown
    peer = server
    d = driver(peer, <<~CONF)
      <buffer tag>
        @type file
        path #{peer.directory}/shutdown-buffer
        flush_mode immediate
        flush_at_shutdown false
        flush_thread_interval 0.01
      </buffer>
    CONF
    item = d.instance.logger('my.app.fid').transport
    waiting, release = Queue.new, Queue.new
    item.define_singleton_method(:do_write) do |_data|
      waiting << true
      release.pop
      raise IOError, 'inflight flush interrupted'
    end
    d.run(flush: false, wait_flush_completion: false, default_tag: 'my.app.fid') do
      d.feed(1_793_917_801, { 'message' => 'shutdown' })
      Timeout.timeout(3) { waiting.pop }
      @threads << Thread.new { peer.await { item.closed? }; release << true }
    end
    assert_true item.closed?
    assert_true item.socket.closed?
    assert_empty d.instance.instance_variable_get(:@loggers)
    assert_equal 1, peer.connections
    assert_raise(IOError) { d.instance.logger('my.app.late') }
  ensure
    release << true if release
  end

  def test_version_and_packaged_changelog
    spec = Gem::Specification.load(File.expand_path('../../fluent-plugin-devo-radiant.gemspec', __dir__))
    assert_equal '0.1.1', Fluent::Plugin::DevoRadiantConstants::VERSION
    assert_equal '0.1.1', Gem.loaded_specs.fetch('fluent-plugin-devo-radiant').version.to_s
    assert_not_nil spec
    assert_include spec.files, 'CHANGELOG.md'
    assert_include File.read('CHANGELOG.md'), '0.1.1'
  end

  def test_d18_passphrase_configuration_is_secret_and_forwarded
    peer = server
    d = driver(peer, 'client_key_passphrase local-placeholder')
    assert_not_include d.instance.config.to_s, 'local-placeholder'
    assert_include d.instance.config.to_s, 'client_key_passphrase xxxxxx'
    received = nil
    type = Class.new do
      define_singleton_method(:new) { |*_args, **options| received = options; Object.new }
    end
    Fluent::Plugin::DevoRadiantOutput.instance_method(:new_transport).bind_call(d.instance, type)
    assert_equal 'local-placeholder', received[:client_key_passphrase]
    assert_true received[:tls]
  end
end
