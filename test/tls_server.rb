# frozen_string_literal: true

# Copyright 2016 Acquia, Inc.
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

require 'openssl'
require 'socket'
require 'timeout'
require 'tmpdir'
require 'fileutils'

# Connected local socket pairs exercise TLS without requiring a network listener.
# Every socket/thread and generated key belongs to this helper.
class DevoTLSServer
  attr_reader :port, :directory, :cert_path, :key_path, :errors

  def self.certificate(key, name: 'localhost')
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = Random.rand(1..1_000_000)
    cert.subject = cert.issuer = OpenSSL::X509::Name.parse("/CN=#{name}")
    cert.public_key = key.public_to_der.then { |der| OpenSSL::PKey.read(der) }
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 3600
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = factory.issuer_certificate = cert
    cert.add_extension(factory.create_extension('basicConstraints', 'CA:TRUE', true))
    cert.add_extension(factory.create_extension('subjectAltName', 'DNS:localhost,IP:127.0.0.1'))
    cert.sign(key, OpenSSL::Digest.new('SHA256'))
    cert
  end

  def initialize(plain: false, require_client: false, tls_version: nil, client_ca: nil, before_handshake: nil, &handler)
    @directory = Dir.mktmpdir('devo-tls-', ENV.fetch('DEVO_TEST_TMPDIR', Dir.tmpdir))
    key = OpenSSL::PKey::RSA.new(2048)
    cert = self.class.certificate(key)
    @cert_path = File.join(directory, 'server.crt')
    @key_path = File.join(directory, 'server.key')
    File.write(cert_path, cert.to_pem)
    File.write(key_path, key.private_to_pem, perm: 0o600)
    context = OpenSSL::SSL::SSLContext.new
    context.cert, context.key = cert, key
    if tls_version
      context.min_version = context.max_version = tls_version
    end
    if require_client
      context.verify_mode = OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
      if client_ca
        context.cert_store = OpenSSL::X509::Store.new
        context.cert_store.add_cert(client_ca)
      else
        context.verify_callback = proc { |_ok, _ctx| true } # Only synthetic local clients.
      end
    end
    @context, @plain, @handler, @before_handshake = context, plain, handler, before_handshake
    @port = self.class.next_port
    @streams, @sockets, @threads, @errors, @clients = [], [], [], [], []
    @mutex = Mutex.new
  end

  def self.next_port
    @next_port = (@next_port || 40_000) + 1
  end

  def transport_type(base = FluentPluginDevoRadiant::SyslogTls::SSLTransport)
    peer = self
    Class.new(base) do
      define_method(:get_tcp_connection) { |_address_info = nil| peer.open_client }
    end
  end

  def clients
    @mutex.synchronize { @clients.dup }
  end

  def open_client
    client, raw = Socket.pair(:UNIX, :STREAM, 0)
    @mutex.synchronize { @clients << client; @sockets << raw }
    thread = Thread.new do
      ssl = nil
      begin
        if @plain
          stream = raw
        else
          ssl = OpenSSL::SSL::SSLSocket.new(raw, @context)
          ssl.sync_close = true
          @mutex.synchronize { @sockets << ssl }
          @before_handshake.call(ssl) if @before_handshake
          ssl.accept
          stream = ssl
        end
        index = @mutex.synchronize { @streams << ''.b; @streams.length - 1 }
        if @handler
          @handler.call(stream, self)
        else
          loop do
            data = stream.readpartial(65536)
            @mutex.synchronize { @streams[index] << data }
          end
        end
      rescue EOFError, IOError, SystemCallError, OpenSSL::SSL::SSLError => error
        @mutex.synchronize { @errors << error }
      ensure
        ssl&.close rescue nil
        raw.close rescue nil
      end
    end
    @mutex.synchronize { @threads << thread }
    client
  end

  def bytes
    @mutex.synchronize { @streams.join.dup }
  end

  def connections
    @mutex.synchronize { @streams.length }
  end

  def await(timeout: 5)
    Timeout.timeout(timeout) do
      loop do
        return if yield
        sleep 0.005
      end
    end
  end

  def stop
    @mutex.synchronize { @sockets.dup + @clients.dup }.each { |socket| socket.close rescue nil }
    @mutex.synchronize { @threads.dup }.each { |thread| thread.kill; thread.join }
    FileUtils.remove_entry(directory) if File.directory?(directory)
  end
end
