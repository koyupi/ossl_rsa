require 'date'

# openssl rsa module.
module OsslRsa

  # File process class.
  class FileOp

    # private file.
    PRIVATE_FILE = "private"
    # public file.
    PUBLIC_FILE = "public"
    # pem extension.
    PEM_EXTENSION = ".pem"
    # der extension.
    DER_EXTENSION = ".der"

    # save file private and public key.
    # @param [String] dir_path save dir path. absolute.
    # @param [Hash] key_pair. private and public key pair.
    # @param [integer] mode pem or der.
    # @param [boolean] add_now add now date string flag.
    # @return [Hash] save file path pair. xxx[:private] = private file path, xxx[:public] = public file path.
    def self.save(dir_path, key_pair, mode, add_now=false)

      file_path_pair = create_file_path(dir_path, mode, add_now)

      # save file.
      save_file(key_pair, file_path_pair, mode)
    end

    # save file private and public key.
    # @param [Hash] key_pair. private and public key pair.
    # @param [Hash] save file path pair. xxx[:private] = private file path, xxx[:public] = public file path.
    # @param [integer] mode pem or der.
    # @return [Hash] save file path pair. xxx[:private] = private file path, xxx[:public] = public file path.
    def self.save_file(key_pair, file_path_pair, mode)

      save_path_pair = file_path_pair
      write_mode = get_write_mode(mode)

      # save file.
      unless key_pair[:private].nil?
        write(save_path_pair[:private], write_mode, key_pair[:private])
      else
        save_path_pair[:private] = nil
      end

      unless key_pair[:public].nil?
        write(save_path_pair[:public], write_mode, key_pair[:public])
      else
        save_path_pair[:public] = nil
      end

      save_path_pair
    end

    # create save file path.
    # @param [String] dir_path save dir path. absolute.
    # @param [integer] mode pem or der.
    # @param [boolean] add_now add now date string flag.
    # @return [Hash] save file path pair. xxx[:private] = private file path, xxx[:public] = public file path.
    def self.create_file_path(dir_path, mode, add_now=false)

      # create file path.
      private_path = create_file_name(PRIVATE_FILE, add_now)
      public_path = create_file_name(PUBLIC_FILE, add_now)

      file_path_pair = nil
      # add extension.
      if mode == PEM
        file_path_pair = { private: File.join(dir_path, "#{private_path}#{PEM_EXTENSION}"), public: File.join(dir_path, "#{public_path}#{PEM_EXTENSION}")}
      elsif mode == DER
        file_path_pair = { private: File.join(dir_path, "#{private_path}#{DER_EXTENSION}"), public: File.join(dir_path, "#{public_path}#{DER_EXTENSION}")}
      end
          
      file_path_pair
    end

    # create file name.
    # @param [String] file_name file name.
    # @param [booelan] add_now add now date string flag.
    # @return [String] file name
    def self.create_file_name(file_name, add_now=false)

      # if add_now = false, return file_name
      return file_name unless add_now

      # add date string.
      if add_now
        file_name = "#{file_name}_#{DateTime.now.strftime('%Y%m%d%H%M%S')}"
      end
      file_name
    end

    # get file write mode.
    # @param [String] mode pem or der
    # @return [String] write mode.
    def self.get_write_mode(mode)

      # if pem, return w mode.
      return "w" if mode == PEM

      "wb"
    end

    # write to file.
    # @param [String] file_path save file path.
    # @param [String] write_mode file write mode
    # @param [String] key save key.
    def self.write(file_path, write_mode, key)

      # write to file.
      File.open(file_path, write_mode) do |file|
        file.write(key)
      end
    end
  end
end
