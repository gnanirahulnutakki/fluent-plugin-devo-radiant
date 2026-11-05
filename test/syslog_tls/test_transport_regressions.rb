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
require 'tls_server'
require 'fluent_plugin_devo_radiant/syslog_tls/ssl_transport'

class DevoTransportRegressionTest < Test::Unit::TestCase
  Transport = FluentPluginDevoRadiant::SyslogTls::SSLTransport

  def setup
    @servers, @transports, @threads = [], [], []
  end

  def teardown
    @threads.each { |thread| thread.kill if thread.alive?; thread.join }
    @transports.each(&:close)
    @servers.reverse_each(&:stop)
  end

  def server(**options, &block)
    DevoTLSServer.new(**options, &block).tap { |peer| @servers << peer }
  end

  def transport(peer, type: peer.transport_type, **options)
    type.new('127.0.0.1', peer.port, ca_cert: peer.cert_path, **options).tap { |item| @transports << item }
  end

  def clients_for(port)
    @servers.find { |peer| peer.port == port }.clients.reject(&:closed?)
  end

  def addresses(host, port)
    Socket.getaddrinfo(host, port, Socket::AF_INET, Socket::SOCK_STREAM, nil, nil, false)
  end

  def test_d13_repeated_context_and_handshake_failures_close_tcp_without_gc
    peer = server
    previous = GC.disable
    3.times do
      assert_raise(OpenSSL::SSL::SSLError) do
        peer.transport_type.new('127.0.0.1', peer.port, ca_cert: File.join(peer.directory, 'missing.pem'))
      end
      assert_empty clients_for(peer.port)
      assert_raise(OpenSSL::SSL::SSLError) do
        peer.transport_type.new('127.0.0.1', peer.port)
      end
      assert_empty clients_for(peer.port)
    end
  ensure
    GC.enable unless previous
  end

  def test_d13_handshake_timeout_closes_ssl_and_tcp
    received, eof = Queue.new, Queue.new
    peer = server(plain: true) do |socket, _|
      received << socket.readpartial(65536)
      begin
        loop { socket.readpartial(65536) }
      rescue EOFError
        eof << true
      end
    end
    error = assert_raise(RuntimeError) { transport(peer) }
    assert_equal 'Socket timeout during connect_read', error.message
    assert_operator Timeout.timeout(2) { received.pop }.bytesize, :>, 0
    assert_true Timeout.timeout(2) { eof.pop }
    assert_empty clients_for(peer.port)
  end

  def test_d13_tcp_connect_timeout_closes_each_attempt
    fake = Object.new
    closed = false
    fake.define_singleton_method(:setsockopt) { |*_args| }
    fake.define_singleton_method(:connect_nonblock) { |_address| raise IO::EINPROGRESSWaitWritable }
    fake.define_singleton_method(:close) { closed = true }
    fake.define_singleton_method(:closed?) { closed }
    original = Socket.method(:new)
    Socket.define_singleton_method(:new) { |*_args| fake }
    type = Class.new(Transport) do
      def connect; end

      def select_with_timeout(_socket, _type)
        raise 'injected connect timeout'
      end
    end
    item = type.new('127.0.0.1', 443, tls: false)
    error = assert_raise(RuntimeError) { item.get_tcp_connection }
    assert_equal 'injected connect timeout', error.message
    assert_true closed
  ensure
    Socket.define_singleton_method(:new, original) if original
  end

  def test_d16_tcp_dial_checks_so_error_and_closes_failed_address
    made, waits = [], []
    sockets = [Errno::ECONNREFUSED::Errno, 0].map do |error|
      fake = Object.new
      closed = false
      fake.define_singleton_method(:setsockopt) { |*_args| }
      fake.define_singleton_method(:connect_nonblock) { |_address| raise IO::EINPROGRESSWaitWritable }
      fake.define_singleton_method(:getsockopt) { |*_args| Struct.new(:int).new(error) }
      fake.define_singleton_method(:close) { closed = true }
      fake.define_singleton_method(:closed?) { closed }
      fake
    end
    original = Socket.method(:new)
    Socket.define_singleton_method(:new) { |*_args| sockets.fetch(made.length).tap { |socket| made << socket } }
    candidates = addresses('127.0.0.2', 443) + addresses('127.0.0.1', 443)
    type = Class.new(Transport) do
      def connect; end

      define_method(:resolved_addresses) { candidates }
      define_method(:select_with_timeout) { |socket, kind| waits << [socket, kind]; true }
    end
    item = type.new('127.0.0.1', 443, tls: false)
    assert_same sockets[1], item.get_tcp_connection
    assert_equal 2, made.length
    assert_true sockets[0].closed?
    assert_false sockets[1].closed?
    assert_equal [[sockets[0], :connect_write], [sockets[1], :connect_write]], waits
  ensure
    Socket.define_singleton_method(:new, original) if original
    sockets&.each(&:close)
  end

  def test_d16_tries_later_addresses_after_refusal_for_tls_and_tcp
    [true, false].each do |tls|
      peer = server(plain: !tls)
      candidates = addresses('127.0.0.2', peer.port) + addresses('127.0.0.1', peer.port)
      attempted = []
      type = Class.new(Transport) do
        define_method(:resolved_addresses) { candidates }
        define_method(:get_tcp_connection) do |address_info = nil|
          attempted << address_info[3]
          raise Errno::ECONNREFUSED if address_info[3] != '127.0.0.1'

          peer.open_client
        end
      end
      item = transport(peer, type: type, tls: tls)
      item.write("fallback\n")
      peer.await { peer.bytes == "fallback\n" }
      assert_equal ['127.0.0.2', '127.0.0.1'], attempted
    end
  end

  def test_d16_tries_later_address_after_tls_handshake_failure
    bad, good = server, server
    candidates = addresses('127.0.0.1', bad.port) + addresses('127.0.0.1', good.port)
    type = Class.new(Transport) do
      define_method(:resolved_addresses) { candidates }
      define_method(:get_tcp_connection) { |address_info| address_info[1] == bad.port ? bad.open_client : good.open_client }
    end
    item = transport(good, type: type)
    item.write("trusted-second-address\n")
    good.await { good.bytes == "trusted-second-address\n" }
    assert_empty clients_for(bad.port)
  end

  def test_d16_all_failed_addresses_are_closed
    peer = server(plain: true)
    candidates = addresses('127.0.0.2', peer.port) + addresses('127.0.0.3', peer.port)
    attempted = []
    type = Class.new(Transport) do
      define_method(:resolved_addresses) { candidates }
      define_method(:get_tcp_connection) do |address_info = nil|
        attempted << address_info[3]
        raise Errno::ECONNREFUSED
      end
    end
    assert_raise(Errno::ECONNREFUSED) { transport(peer, type: type, tls: false) }
    assert_equal ['127.0.0.2', '127.0.0.3'], attempted
    assert_empty clients_for(peer.port)
  end

  def test_d17_hashed_ca_directory_with_and_without_slash
    peer = server
    cert = OpenSSL::X509::Certificate.new(File.read(peer.cert_path))
    FileUtils.cp(peer.cert_path, File.join(peer.directory, "#{cert.subject.hash.to_s(16).rjust(8, '0')}.0"))
    [peer.directory, peer.directory + '/'].each do |path|
      item = peer.transport_type.new('127.0.0.1', peer.port, ca_cert: path)
      @transports << item
      item.write("directory\n")
    end
    peer.await { peer.bytes.lines.length == 2 }
    assert_equal ["directory\n", "directory\n"], peer.bytes.lines
  end

  def test_d18_encrypted_rsa_and_ec_keys_connect_without_prompt
    [OpenSSL::PKey::RSA.new(2048), OpenSSL::PKey::EC.generate('prime256v1')].each do |key|
      peer = server(require_client: true, tls_version: OpenSSL::SSL::TLS1_2_VERSION)
      cert_path = File.join(peer.directory, 'client.crt')
      key_path = File.join(peer.directory, 'encrypted.key')
      File.write(cert_path, DevoTLSServer.certificate(key).to_pem)
      File.write(key_path, key.private_to_pem(OpenSSL::Cipher.new('aes-256-cbc'), 'local-test-passphrase'), perm: 0o600)
      item = transport(peer, client_cert: cert_path, client_key: key_path, client_key_passphrase: 'local-test-passphrase')
      item.write("encrypted-key\n")
      peer.await { peer.bytes == "encrypted-key\n" }
      assert_equal "encrypted-key\n", peer.bytes
      assert_raise(OpenSSL::PKey::PKeyError) do
        transport(peer, client_cert: cert_path, client_key: key_path, client_key_passphrase: 'wrong')
      end
      assert_raise(OpenSSL::PKey::PKeyError) do
        transport(peer, client_cert: cert_path, client_key: key_path)
      end
    end
  end

  def issue(key, name, issuer: nil, issuer_key: key, ca: false)
    cert = OpenSSL::X509::Certificate.new
    cert.version, cert.serial = 2, Random.rand(1..1_000_000)
    cert.subject = OpenSSL::X509::Name.parse("/CN=#{name}")
    cert.issuer = issuer ? issuer.subject : cert.subject
    cert.public_key = OpenSSL::PKey.read(key.public_to_der)
    cert.not_before, cert.not_after = Time.now - 60, Time.now + 3600
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate, factory.issuer_certificate = cert, issuer || cert
    cert.add_extension(factory.create_extension('basicConstraints', ca ? 'CA:TRUE' : 'CA:FALSE', true))
    cert.add_extension(factory.create_extension('keyUsage', ca ? 'keyCertSign,cRLSign' : 'digitalSignature,keyEncipherment', true))
    cert.sign(issuer_key, OpenSSL::Digest.new('SHA256'))
    cert
  end

  def test_d19_sends_intermediate_chain_to_root_only_mtls_peer
    root_key, inter_key, leaf_key = 3.times.map { OpenSSL::PKey::EC.generate('prime256v1') }
    root = issue(root_key, 'root', ca: true)
    inter = issue(inter_key, 'intermediate', issuer: root, issuer_key: root_key, ca: true)
    leaf = issue(leaf_key, 'client', issuer: inter, issuer_key: inter_key)
    peer = server(require_client: true, client_ca: root, tls_version: OpenSSL::SSL::TLS1_2_VERSION)
    cert_path, key_path = File.join(peer.directory, 'client.crt'), File.join(peer.directory, 'client.key')
    File.write(cert_path, leaf.to_pem + inter.to_pem)
    File.write(key_path, leaf_key.private_to_pem, perm: 0o600)
    item = transport(peer, client_cert: cert_path, client_key: key_path)
    item.write("full-chain\n")
    peer.await { peer.bytes == "full-chain\n" }
    assert_equal "full-chain\n", peer.bytes
    context = item.send(:build_ssl_context)
    assert_equal leaf.to_der, context.cert.to_der
    assert_equal [inter.to_der], context.extra_chain_cert.map(&:to_der)
    item.close
    File.write(cert_path, leaf.to_pem)
    assert_raise(OpenSSL::SSL::SSLError) { transport(peer, client_cert: cert_path, client_key: key_path) }
    assert_empty clients_for(peer.port)
  end

  def test_d15_close_during_write_never_reconnects_and_closes_once
    peer = server(plain: true)
    item = transport(peer, tls: false, max_retries: 3)
    waiting, release = Queue.new, Queue.new
    connects = 0
    original_connect = item.method(:connect)
    item.define_singleton_method(:connect) { connects += 1; original_connect.call }
    item.define_singleton_method(:do_write) { |_data| waiting << true; release.pop; raise IOError, 'inflight failure' }
    errors = Queue.new
    writer = Thread.new { item.write('message') rescue errors << $! }
    @threads << writer
    Timeout.timeout(2) { waiting.pop }
    raw = item.socket
    closes = 0
    original_close = raw.method(:close)
    raw.define_singleton_method(:close) { closes += 1; original_close.call }
    closer = Thread.new { item.close }
    @threads << closer
    peer.await { item.closed? }
    release << true
    assert_not_nil writer.join(2)
    assert_not_nil closer.join(2)
    assert_kind_of IOError, errors.pop
    2.times { item.close }
    assert_raise(IOError) { item.write('late write') }
    assert_equal 0, connects
    assert_raise(IOError) { item.connect }
    assert_equal 1, closes
    assert_true raw.closed?
  ensure
    release << true if release
  end

  def test_d21_tls_and_tcp_share_retry_and_write_timeout_behavior
    [true, false].each do |tls|
      peer = server(plain: !tls)
      item = transport(peer, tls: tls, max_retries: 2)
      first_socket = item.socket
      original_write = item.method(:do_write)
      attempts = 0
      item.define_singleton_method(:do_write) do |data|
        attempts += 1
        raise IOError, 'transient write failure' if attempts == 1

        original_write.call(data)
      end
      item.write("retried\n")
      peer.await { peer.bytes == "retried\n" }
      assert_equal 2, attempts
      assert_true first_socket.closed?
      assert_not_same first_socket, item.socket
      item.define_singleton_method(:do_write) { |_data| raise 'Socket timeout during write' }
      assert_raise(RuntimeError) { item.write('timeout') }
      assert_true item.socket.closed?
    end
  end
end
