# -*- coding:binary -*-

require 'openssl' unless defined? OpenSSL::Digest
require 'metasploit-payloads/version' unless defined? MetasploitPayloads::VERSION
require 'metasploit-payloads/error' unless defined? MetasploitPayloads::Error
require 'metasploit-payloads/crypto' unless defined? MetasploitPayloads::Crypto

#
# This module dispenses Metasploit payload binary files
#
module MetasploitPayloads
  EXTENSION_PREFIX      = 'ext_server_'
  METERPRETER_SUBFOLDER = 'meterpreter'
  USER_DATA_SUBFOLDER   = 'payloads'

  #
  # @return [Array<Hash<String, Symbol>>] An array of filenames with warnings. Provides a file name and error.
  #  Empty if all needed Meterpreter files exist and have the correct hash.
  def self.manifest_errors
    manifest_errors = []

    begin
      manifest_contents = ::File.binread(manifest_path)
    rescue => e
      return [{ path: manifest_path, error: e }]
    end

    begin
      manifest_uuid_contents = ::File.binread(manifest_uuid_path)
    rescue => e
      manifest_errors.append({ path: manifest_uuid_path, error: e })
    end

    # Check if the hash of the manifest file is correct.
    if manifest_uuid_contents
      manifest_digest = ::OpenSSL::Digest.new('SHA3-256', manifest_contents)
      uuid_matches = (manifest_uuid_contents.chomp == manifest_digest.to_s)
      unless uuid_matches
        e = ::MetasploitPayloads::HashMismatchError.new(manifest_path)
        manifest_errors.append({ path: manifest_path, error: e })
      end
    end

    manifest_contents.each_line do |line|
      filename, hash_type, hash = line.chomp.split(':')
      begin
        filename = filename.sub('./data/', '')
        # self.path prepends the gem data directory, which is already present in the manifest file.
        out_path = self.path(filename)
        # self.path can return a path to the gem data, or user's local data.
        bundled_file = out_path.start_with?(data_directory)
        if bundled_file
          file_hash_match = (::OpenSSL::Digest.new(hash_type, ::File.binread(out_path)).to_s == hash)
          unless file_hash_match
            e = ::MetasploitPayloads::HashMismatchError.new(out_path)
            manifest_errors.append({ path: e.path, error: e })
          end
        end
      rescue ::MetasploitPayloads::NotFoundError, ::MetasploitPayloads::NotReadableError => e
        manifest_errors.append({ path: e.path, error: e })
      end
    end

    manifest_errors
  end

  #
  # Get the path to an extension based on its name (no prefix).
  #
  def self.meterpreter_ext_path(ext_name, binary_suffix)
    path(METERPRETER_SUBFOLDER, "#{EXTENSION_PREFIX}#{ext_name}.#{binary_suffix}")
  end

  #
  # Get the path for the first readable path in the provided arguments.
  # Start with the provided `extra_paths` then fall back to the `gem_path`.
  #
  # @param [String] gem_path a path to the gem
  # @param [Array<String>] extra_paths a path to any extra paths that should be evaluated for local files before `gem_path`
  # @raise [NotReadableError] if the user doesn't have read permissions for the currently-evaluated path
  # @return [String,nil] A readable path or nil
  def self.readable_path(gem_path, *extra_paths)
    # Try the MSF path first to see if the file exists, allowing the MSF data
    # folder to override what is in the gem. This is very helpful for
    # testing/development without having to move the binaries to the gem folder
    # each time. We only do this is MSF is installed.
    extra_paths.each do |extra_path|
      if ::File.readable? extra_path
        warn_local_path(extra_path)
        return extra_path
      else
        # Raise rather than falling back;
        # If there is a local file present, let's assume that the user wants to use it (e.g. local dev. changes)
        # rather than having MSF Console falling back to the files in the gem
        raise ::MetasploitPayloads::NotReadableError, extra_path, caller if ::File.exist?(extra_path)
      end
    end

    return gem_path if ::File.readable? gem_path
    raise ::MetasploitPayloads::NotReadableError, gem_path, caller if ::File.exist?(gem_path)

    nil
  end

  #
  # Get the path to a meterpreter binary by full name.
  #
  # @param [String] name The name of the requested binary without any file extensions
  # @param [String] binary_suffix The binary extension, without the leading '.' char (e.g. `php`, `jar`)
  # @param [Boolean] debug Request a debug version of the binary. This adds a
  #  leading '.debug' to the extension if looking for a DLL file.
  def self.meterpreter_path(name, binary_suffix, debug: false)
    binary_suffix = binary_suffix&.gsub(/dll$/, 'debug.dll') if debug
    path(METERPRETER_SUBFOLDER, "#{name}.#{binary_suffix}".downcase)
  end

  #
  # Get the full path to any file packaged in this gem or other Metasploit Framework directories by local path and name.
  #
  # @param [Array<String>] path_parts requested path parts that will be joined
  # @raise [NotFoundError] if the requested path/file does not exist
  # @raise [NotReadableError] if the requested file exists but the user doesn't have read permissions
  # @return [String,nil] A path or nil
  def self.path(*path_parts)
    gem_path = expand(data_directory, ::File.join(path_parts))
    if metasploit_installed?
      user_path = expand(Msf::Config.config_directory, ::File.join(USER_DATA_SUBFOLDER, path_parts))
      msf_path = expand(Msf::Config.data_directory, ::File.join(path_parts))
      out_path = readable_path(gem_path, user_path, msf_path)
    else
      out_path = readable_path(gem_path)
    end

    return out_path unless out_path.nil?
    raise ::MetasploitPayloads::NotFoundError, ::File.join(gem_path), caller unless ::File.exist?(gem_path)

    nil
  end

  #
  # Get the contents of any file packaged in this gem by local path and name.
  # If the file is encrypted using ChaCha20, automatically decrypt it and return the file contents.
  #
  def self.read(*path_parts)
    file_path = self.path(path_parts)

    begin
      file_contents = ::File.binread(file_path)
    rescue ::Errno::ENOENT => _e
      raise ::MetasploitPayloads::NotFoundError, file_path, caller
    rescue ::Errno::EACCES => _e
      raise ::MetasploitPayloads::NotReadableError, file_path, caller
    rescue ::StandardError => e
      raise e
    end

    Crypto.decrypt(ciphertext: file_contents)
  end

  #
  # List all the available extensions, optionally filtered by the given suffix.
  #
  # @param [String] binary_suffix An optional suffix to use for filtering results. If omitted, all extensions will be
  #   returned.
  # @return [Array<String>] Returns an array of extensions.
  def self.list_meterpreter_extensions(binary_suffix=nil)
    list_meterpreter_dirs { |dir| meterpreter_enum_ext(dir, binary_suffix) }
  end

  #
  # List all the available suffixes, optionally filtered by the given extension name. This is mostly useful for
  # determining support for a specific extension.
  #
  # @param [String] extension_name An optional extension name to use for filtering results. If omitted, all suffixes
  #   will be returned.
  # @return [Array<String>] Returns an array of binary suffixes.
  def self.list_meterpreter_extension_suffixes(extension_name=nil)
    list_meterpreter_dirs { |dir| meterpreter_enum_ext_suffixes(dir, extension_name) }
  end

  #
  # Full path to the local gem folder containing the base data
  #
  def self.data_directory
    ::File.realpath(::File.join(::File.dirname(__FILE__), '..', 'data'))
  end

  #
  # Full path to the MSF data folder which contains the meterpreter binaries.
  #
  def self.msf_meterpreter_dir
    ::File.join(Msf::Config.data_directory, METERPRETER_SUBFOLDER)
  end

  #
  # Full path to the user's MSF data folder which contains the meterpreter binaries.
  #
  def self.user_meterpreter_dir
    ::File.join(Msf::Config.config_directory, USER_DATA_SUBFOLDER, METERPRETER_SUBFOLDER)
  end

  #
  # Full path to the local gem folder which contains the meterpreter binaries.
  #
  def self.local_meterpreter_dir
    ::File.join(data_directory, METERPRETER_SUBFOLDER)
  end

  #
  # Enumerate extensions in the given root folder based on an optional suffix.
  #
  # @param [String] root_dir The path to the directory from which to enumerate extensions.
  # @param [String] binary_suffix An optional suffix to use for filtering results. If omitted, all extensions will be
  #   returned.
  # @return [Array<String>] Returns an array of extensions.
  def self.meterpreter_enum_ext(root_dir, binary_suffix=nil)
    exts = []
    binary_suffix ||= '.*'
    ::Dir.entries(root_dir).each do |f|
      if ::File.readable?(::File.join(root_dir, f)) && \
         f =~ /#{EXTENSION_PREFIX}(\w+)\.#{binary_suffix}/
        exts.push($1)
      end
    end
    exts
  end

  #
  # Enumerate binary suffixes in the given root folder based on an optional extension name.
  #
  # @param [String] root_dir The path to the directory from which to enumerate extension suffixes.
  # @param [String] extension_name An optional extension name to use for filtering results. If omitted, all suffixes will
  #   be returned.
  # @return [Array<String>] Returns an array of binary suffixes.
  def self.meterpreter_enum_ext_suffixes(root_dir, extension_name=nil)
    suffixes = []
    extension_name ||= '\w+'
    ::Dir.entries(root_dir).each do |f|
      if ::File.readable?(::File.join(root_dir, f)) && \
         f =~ /#{EXTENSION_PREFIX}#{extension_name}\.(\w+(\.\w+)*)/
        suffixes.push($1)
      end
    end
    suffixes
  end

  private

  #
  # Determine if MSF has been installed and is being used.
  #
  def self.metasploit_installed?
    defined? Msf::Config
  end

  #
  # Expand the given root path and file name into a full file location.
  #
  def self.expand(root_dir, file_name)
    ::File.expand_path(::File.join(root_dir, file_name))
  end

  @local_paths = []

  def self.warn_local_path(path)
    STDERR.puts("WARNING: Local file #{path} is being used")
    STDERR.puts('WARNING: Local files may be incompatible with the Metasploit Framework') if @local_paths.empty?
    @local_paths << path
    @local_paths.uniq!
  end

  class << self
    private
    def list_meterpreter_dirs(&block)
      things = [] # *things* is whatever is being enumerated (extension names, suffixes, etc.) as determined by the block
      root_dirs = [local_meterpreter_dir]

      # Find the valid extensions in the data folder first, if MSF
      # is installed.
      if metasploit_installed?
        root_dirs.unshift(msf_meterpreter_dir)
        root_dirs.unshift(user_meterpreter_dir)
      end

      root_dirs.each do |dir|
        next unless ::File.directory?(dir)

        # Merge in any that don't already exist in the collection.
        (yield dir).each do |e|
          things.push(e) unless things.include?(e)
        end
      end

      things
    end

    def manifest_path
      ::File.realpath(::File.join(::File.dirname(__FILE__), '..', 'manifest'))
    end

    def manifest_uuid_path
      ::File.realpath(::File.join(::File.dirname(__FILE__), '..', 'manifest.uuid'))
    end
  end
end
