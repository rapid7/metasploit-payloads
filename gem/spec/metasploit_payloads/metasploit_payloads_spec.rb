# frozen_string_literal: true

require 'metasploit-payloads'

RSpec.describe ::MetasploitPayloads do
  describe '::VERSION' do
    it 'has a version number' do
      expect(::MetasploitPayloads::VERSION).not_to be nil
    end
  end

  describe '::Error' do
    it 'has an Error class' do
      expect(::MetasploitPayloads::Error.superclass).to be(::StandardError)
    end

    it 'has a NotFoundError class' do
      expect(::MetasploitPayloads::NotFoundError.superclass).to be(::MetasploitPayloads::Error)
    end

    it 'has a NotReadableError class' do
      expect(::MetasploitPayloads::NotReadableError.superclass).to be(::MetasploitPayloads::Error)
    end

    it 'has a HashMismatchError class' do
      expect(::MetasploitPayloads::HashMismatchError.superclass).to be(::MetasploitPayloads::Error)
    end
  end

  describe '#readable_path' do
    let(:sample_file) { { name: 'meterpreter/meterpreter.py' } }

    before :each do
      allow(::File).to receive(:exist?).and_call_original
      allow(::File).to receive(:readable?).and_call_original
    end

    context 'when the path is not readable' do
      it 'raises a ::MetasploitPayloads::NotReadableError' do
        allow(::File).to receive(:exist?).with(sample_file[:name]).and_return(true)
        allow(::File).to receive(:readable?).with(sample_file[:name]).and_return(false)

        expect { subject.readable_path(sample_file[:name]) }.to raise_error(::MetasploitPayloads::NotReadableError)
      end
    end

    context 'when the path does not exist' do
      it 'returns nil' do
        allow(::File).to receive(:exist?).with(sample_file[:name]).and_return(false)
        allow(::File).to receive(:readable?).with(sample_file[:name]).and_return(false)

        expect(subject.readable_path(sample_file[:name])).to eq(nil)
      end
    end

    context 'when the path exists and is readable' do
      it 'returns the correct path' do
        allow(::File).to receive(:exist?).with(sample_file[:name]).and_return(true)
        allow(::File).to receive(:readable?).with(sample_file[:name]).and_return(true)

        expect(subject.readable_path(sample_file[:name])).to eq(sample_file[:name])
      end
    end
  end

  describe '#path' do
    let(:sample_file) { { name: 'meterpreter/meterpreter.py' } }

    before :each do
      allow(::File).to receive(:exist?).and_call_original
      allow(::File).to receive(:readable?).and_call_original
      allow(::MetasploitPayloads).to receive(:expand).and_call_original

      allow(::MetasploitPayloads).to receive(:expand)
        .with(::MetasploitPayloads.data_directory, sample_file[:name])
        .and_return(sample_file[:name])
    end

    [
      { context: 'is not readable', exist: true, readable: false, expected: ::MetasploitPayloads::NotReadableError },
      { context: 'does not exist', exist: false, readable: false, expected: ::MetasploitPayloads::NotFoundError }
    ].each do |test|
      context "when the path #{test[:context]}" do
        it "raises #{test[:expected]}" do
          allow(::File).to receive(:exist?).with(sample_file[:name]).and_return(test[:exist])
          allow(::File).to receive(:readable?).with(sample_file[:name]).and_return(test[:readable])

          expect { subject.path(sample_file[:name]) }.to raise_error(test[:expected])
        end
      end
    end

    context 'when the path exists and is readable' do
      it 'returns the correct path' do
        allow(::File).to receive(:exist?).with(sample_file[:name]).and_return(true)
        allow(::File).to receive(:readable?).with(sample_file[:name]).and_return(true)

        expect(subject.path(sample_file[:name])).to eq(sample_file[:name])
      end
    end
  end

  describe '#manifest_errors' do
    let(:hash_type) { 'SHA3-256' }
    let(:hash) { { type: hash_type, value: '92e931e6b47caad6df4249cc263fdbe5d2975c4163f5b06963208163b7af97b5' } }
    let(:sample_file) { { name: 'meterpreter/ext_server_stdapi.php', contents: 'sample_data', hash: hash } }
    let(:manifest_values) { ["./data/#{sample_file[:name]}", sample_file[:hash][:type], sample_file[:hash][:value]] }
    let(:manifest) { manifest_values.join(':') }
    let(:manifest_uuid) { ::OpenSSL::Digest.new(hash_type, manifest).to_s }
    let(:manifest_path) { 'manifest' }
    let(:manifest_uuid_path) { 'manifest.uuid' }

    before :each do
      allow(::MetasploitPayloads).to receive(:manifest_path).and_call_original
      allow(::MetasploitPayloads).to receive(:manifest_path).and_return(manifest_path)

      allow(::MetasploitPayloads).to receive(:manifest_uuid_path).and_call_original
      allow(::MetasploitPayloads).to receive(:manifest_uuid_path).and_return(manifest_uuid_path)

      allow(::File).to receive(:binread).and_call_original
      allow(::File).to receive(:binread).with(sample_file[:name]).and_return(sample_file[:contents])
      allow(::File).to receive(:binread).with(::MetasploitPayloads.send(:manifest_path)).and_return(manifest)
      allow(::File).to receive(:binread).with(::MetasploitPayloads.send(:manifest_uuid_path)).and_return(manifest_uuid)

      allow(::OpenSSL::Digest).to receive(:new).and_call_original
      allow(::OpenSSL::Digest).to receive(:new).with(hash_type,
                                                     sample_file[:contents]).and_return(sample_file[:hash][:value])
    end

    context 'when manifest hash does not match' do
      it 'result includes the manifest file' do
        allow(::File).to receive(:binread).with(::MetasploitPayloads.send(:manifest_uuid_path))
                                          .and_return('mismatched_manifest_hash')
        path = ::MetasploitPayloads.send(:manifest_path)
        e = ::MetasploitPayloads::HashMismatchError.new(path)

        expect(subject.manifest_errors).to include({ path: path, error: e })
      end
    end

    context 'when manifest hash does match' do
      it 'result does not include manifest' do
        path = ::MetasploitPayloads.send(:manifest_uuid_path)
        e = ::MetasploitPayloads::HashMismatchError.new(path)

        expect(subject.manifest_errors).not_to include({ path: path, error: e })
      end
    end

    context 'when there are no file warnings' do
      it 'returns an empty array' do
        allow(::MetasploitPayloads).to receive(:path).with(sample_file[:name]).and_return(sample_file[:name])
        allow(::File).to receive(:exist?).with(sample_file[:name]).and_return(true)
        full_file_path = ::MetasploitPayloads.expand(::MetasploitPayloads.data_directory, sample_file[:name])
        allow(::File).to receive(:readable?).with(full_file_path).and_return(true)
        allow(::File).to receive(:binread).with(full_file_path).and_return(sample_file[:contents])

        expect(subject.manifest_errors).to eq([])
      end
    end

    [
      { context: 'does not exist', error_class: ::MetasploitPayloads::NotFoundError },
      { context: 'is not readable', error_class: ::MetasploitPayloads::NotReadableError }
    ].each do |test|
      context "when a file #{test[:context]}" do
        it 'includes the correct error' do
          error = test[:error_class].new(sample_file[:name])
          allow(::MetasploitPayloads).to receive(:path).with(sample_file[:name]).and_raise(error)

          expect(subject.manifest_errors).to include({ path: sample_file[:name], error: error })
        end
      end
    end

    context 'when a bundled file hash does not match' do
      it 'includes the correct error' do
        allow(::File).to receive(:exist?).with(sample_file[:name]).and_return(true)
        full_file_path = ::MetasploitPayloads.expand(::MetasploitPayloads.data_directory, sample_file[:name])
        allow(::File).to receive(:readable?).with(full_file_path).and_return(true)
        allow(::File).to receive(:binread).with(full_file_path).and_return('mismatched_file_contents')
        e = ::MetasploitPayloads::HashMismatchError.new(full_file_path)

        expect(subject.manifest_errors).to include({ path: full_file_path, error: e })
      end
    end

    context 'when the manifest file' do
      context 'does not exist' do
        it 'only includes the manifest error' do
          # path = ::MetasploitPayloads.send(:manifest_path)
          e = ::Errno::ENOENT.new(manifest_path)
          allow(::File).to receive(:binread).with(manifest_path).and_raise(e)

          expect(subject.manifest_errors).to eq([{ path: manifest_path, error: e }])
        end
      end

      context 'cannot be read' do
        it 'only includes the manifest error' do
          e = ::Errno::EACCES.new(manifest_path)
          allow(::File).to receive(:binread).with(manifest_path).and_raise(e)

          expect(subject.manifest_errors).to eq([{ path: manifest_path, error: e }])
        end
      end
    end

    context 'when the manifest.uuid file' do
      context 'does not exist' do
        it 'includes the correct error' do
          e = ::Errno::ENOENT.new(manifest_uuid_path)
          allow(::File).to receive(:binread).with(manifest_uuid_path).and_raise(e)

          expect(subject.manifest_errors).to include({ path: manifest_uuid_path, error: e })
        end
      end
    end

    context 'when manifest is readable and manifest.uuid is not readable' do
      before :each do
        allow(::File).to receive(:binread).with(manifest_uuid_path).and_raise(::Errno::EACCES.new(manifest_uuid_path))
      end

      it 'correctly evaluates a file hash mismatch' do
        bundled_file_path = ::MetasploitPayloads.expand(::MetasploitPayloads.data_directory, sample_file[:name])
        error = ::MetasploitPayloads::HashMismatchError.new(bundled_file_path)
        allow(::MetasploitPayloads).to receive(:path).with(sample_file[:name]).and_return(bundled_file_path)
        allow(::File).to receive(:binread).with(bundled_file_path).and_return('sample_mismatched_contents')

        expect(subject.manifest_errors).to include({ path: bundled_file_path, error: error })
      end

      it 'correctly evaluates a missing file' do
        error = ::MetasploitPayloads::NotFoundError.new(sample_file[:name])
        allow(::MetasploitPayloads).to receive(:path).with(sample_file[:name]).and_raise(error)

        expect(subject.manifest_errors).to include({ path: sample_file[:name], error: error })
      end

      it 'correctly evaluates an unreadable file' do
        error = ::MetasploitPayloads::NotReadableError.new(sample_file[:name])
        allow(::MetasploitPayloads).to receive(:path).with(sample_file[:name]).and_raise(error)

        expect(subject.manifest_errors).to include({ path: sample_file[:name], error: error })
      end
    end
  end

  describe '#read' do
    let(:encrypted_header) { "msf\x02\x01\x01" }
    let(:raw_file) { { name: 'meterpreter.py', contents: 'sample_file_contents' } }
    # AES-256-CBC encrypted contents
    let(:encrypted_contents) { "\xEA\x00q\xEB\a\xCA\xD2\xD3\xE2',N\x86\x1C\f?\xBE\xC4\x8AJRks\xAD\xD6\xDF\xA3.\xCD\xA7\x84\xD2".b }
    let(:encrypted_file) { { name: raw_file[:name], contents: encrypted_header + encrypted_contents } }

    before :each do
      allow(::MetasploitPayloads).to receive(:path).and_call_original
      allow(::MetasploitPayloads).to receive(:path).with([encrypted_file[:name]]).and_return(encrypted_file[:name])
      allow(::MetasploitPayloads).to receive(:path).with([raw_file[:name]]).and_return(raw_file[:name])

      allow(::File).to receive(:binread).and_call_original
      allow(::File).to receive(:binread).with(encrypted_file[:name]).and_return(encrypted_file[:contents])
      allow(::File).to receive(:binread).with(raw_file[:name]).and_return(raw_file[:contents])
    end

    context 'an encrypted file' do
      it 'returns plain-text file contents' do
        expect(subject.read(encrypted_file[:name])).to eq(raw_file[:contents])
      end
    end

    context 'a plain-text file' do
      it 'returns plain-text file contents' do
        expect(subject.read(raw_file[:name])).to eq(raw_file[:contents])
      end
    end
  end
end
