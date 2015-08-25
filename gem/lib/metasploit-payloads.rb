# -*- coding:binary -*-

unless defined? MetasploitPayloads::VERSION
  require 'metasploit-payloads/version'
end

#
# This module dispenses Metasploit payload binary files
#
module MetasploitPayloads
  EXTENSION_PREFIX      = 'ext_server_'
  METERPRETER_SUBFOLDER = 'meterpreter'

  #
  # Get the path to an extension based on its name (no prefix).
  #
  def self.meterpreter_ext_path(ext_name, binary_suffix)
    path("#{EXTENSION_PREFIX}#{ext_name}", binary_suffix)
  end

  def self.readable_path(gem_path, msf_path)
    # Try the MSF path first to see if the file exists, allowing the MSF data
    # folder to override what is in the gem. This is very helpful for
    # testing/development without having to move the binaries to the gem folder
    # each time. We only do this is MSF is installed.
    if ::File.readable? msf_path
      warn_local_path(msf_path) if ::File.readable? gem_path
      return msf_path

    elsif ::File.readable? gem_path
      return gem_path
    end

    nil
  end

  #
  # Get the path to a meterpreter binary by full name.
  #
  def self.meterpreter_path(name, binary_suffix)
    file_name = "#{name}.#{binary_suffix}".downcase
    gem_path = expand(local_meterpreter_dir, file_name)
    if metasploit_installed?
      msf_path = expand(msf_meterpreter_dir, file_name)
    end
    readable_path(gem_path, msf_path)
  end

  #
  # Get the full path to any file packaged in this gem by local path and name.
  #
  def self.path(*path_parts)
    gem_path = expand(data_directory, ::File.join(path_parts))
    if metasploit_installed?
      msf_path = expand(Msf::Config.data_directory, ::File.join(path_parts))
    end
    readable_path(gem_path, msf_path)
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
  # List all the available extensions for the given suffix.
  #
  def self.list_meterpreter_extensions(binary_suffix)
    extensions = []

    root_dirs = [local_meterpreter_dir]

    # Find the valid extensions in the data folder first, if MSF
    # is installed.
    root_dirs.unshift(msf_meterpreter_dir) if metasploit_installed?

    root_dirs.each do |dir|
      # Merge in any that don't already exist in the collection.
      meterpreter_enum_ext(dir, binary_suffix).each do |e|
        extensions.push(e) unless extensions.include?(e)
      end
    end

    extensions
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
  # Full path to the local gem folder which contains the meterpreter binaries.
  #
  def self.local_meterpreter_dir
    ::File.join(data_directory, METERPRETER_SUBFOLDER)
  end

  #
  # Enumerate extensions in the given root folder based on the suffix.
  #
  def self.meterpreter_enum_ext(root_dir, binary_suffix)
    exts = []
    ::Dir.entries(root_dir).each do |f|
      if ::File.readable?(::File.join(root_dir, f)) && \
         f =~ /#{EXTENSION_PREFIX}(.*)\.#{binary_suffix}/
        exts.push($1)
      end
    end
    exts
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
      if @local_paths.empty?
        STDERR.puts('WARNING: Local files may be incompatible Metasploit framework')
      end
      @local_paths << path
    end
  end
end
