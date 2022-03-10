# -*- coding:binary -*-

require 'metasploit-payloads/version' unless defined? MetasploitPayloads::VERSION

#
# This module dispenses Metasploit payload binary files
#
module MetasploitPayloads
  EXTENSION_PREFIX      = 'ext_server_'
  METERPRETER_SUBFOLDER = 'meterpreter'
  USER_DATA_SUBFOLDER   = 'payloads'

  #
  # Get the path to an extension based on its name (no prefix).
  #
  def self.meterpreter_ext_path(ext_name, binary_suffix)
    path(METERPRETER_SUBFOLDER, "#{EXTENSION_PREFIX}#{ext_name}.#{binary_suffix}")
  end

  def self.readable_path(gem_path, *extra_paths)
    # Try the MSF path first to see if the file exists, allowing the MSF data
    # folder to override what is in the gem. This is very helpful for
    # testing/development without having to move the binaries to the gem folder
    # each time. We only do this is MSF is installed.
    extra_paths.each do |extra_path|
      if ::File.readable? extra_path
        warn_local_path(extra_path) if ::File.readable? gem_path
        return extra_path
      end
    end

    return gem_path if ::File.readable? gem_path

    nil
  end

  #
  # Get the path to a meterpreter binary by full name.
  #
  def self.meterpreter_path(name, binary_suffix, debug: false)
    binary_suffix = binary_suffix&.gsub(/dll$/, 'debug.dll') if debug
    path(METERPRETER_SUBFOLDER, "#{name}.#{binary_suffix}".downcase)
  end

  #
  # Get the full path to any file packaged in this gem by local path and name.
  #
  def self.path(*path_parts)
    gem_path = expand(data_directory, ::File.join(path_parts))
    if metasploit_installed?
      user_path = expand(Msf::Config.config_directory, ::File.join(USER_DATA_SUBFOLDER, path_parts))
      msf_path = expand(Msf::Config.data_directory, ::File.join(path_parts))
    end
    readable_path(gem_path, user_path, msf_path)
  end

  #
  # Get the contents of any file packaged in this gem by local path and name.
  #
  def self.read(*path_parts)
    file_path = path(path_parts)
    if file_path.nil?
      full_path = ::File.join(path_parts)
      fail RuntimeError, "#{full_path} not found", caller
    end

    ::File.binread(file_path)
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
    unless @local_paths.include?(path)
      STDERR.puts("WARNING: Local file #{path} is being used")
      STDERR.puts('WARNING: Local files may be incompatible with the Metasploit Framework') if @local_paths.empty?
      @local_paths << path
    end
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
  end
end
