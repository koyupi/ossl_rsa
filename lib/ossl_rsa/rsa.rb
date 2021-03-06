require "ossl_rsa/generator"
require "openssl"
require "base64"
require "securerandom"

# openssl rsa module.
module OsslRsa

  # rsa class
  class Rsa

    # constructor.
    # generate rsa instance by options.
    # options[:size] : key size
    # options[:obj] : pem or der
    # options[:pass] : password
    # @param [Hash] options generate options.
    def initialize(options={})

      # generate rsa instance.
      @rsa = OsslRsa::Generator.generate(options)
    end

    # encrypt RSA. use public_key.
    # @param [String] value encrypt target value.
    # @param [integer] mode padding mode.
    # @param [boolean] base64_encode base64 encode flag.
    # @return [String] encrypt value.
    def encrypt(value, mode=OpenSSL::PKey::RSA::PKCS1_PADDING, base64_encode=true)

      # not public, return nil.
      return nil unless @rsa.public?

      encrypt_value = @rsa.public_encrypt(value, mode)
      # base64 encode.
      if base64_encode
        encrypt_value = encode_base64(encrypt_value)
      end
      encrypt_value
    end

    # decrypt RSA. use private_key.
    # @param [String] value decrypt target value.
    # @param [integer] mode padding mode.
    # @param [boolean] base64_decode base64 decode flag.
    # @return [String] decrypt value.
    def decrypt(value, mode=OpenSSL::PKey::RSA::PKCS1_PADDING, base64_decode=true)

      # not private, return nil.
      return nil unless @rsa.private?

      # base64 decode
      if base64_decode
        value = decode_base64(value)
      end

      decrypt_value = @rsa.private_decrypt(value, mode)
      decrypt_value
    end

    # sign data.
    # @param [String] digest digest method.
    # @param [String] value sign target value.
    # @param [boolean] base64_encode base64 encode flag.
    # @return [String] sign value.
    def sign(digest, value, base64_encode=true)

      # not private, return nil.
      return nil unless @rsa.private?

      sign_value = @rsa.sign(digest, value)
      # base64 encode.
      if base64_encode
        sign_value = encode_base64(sign_value)
      end
      sign_value
    end

    # verify sign value.
    # @param [String] digest digest method.
    # @param [String] sign sign value.
    # @param [String] value compare target value.
    # @param [boolean] base64_decode base64 decode flag.
    # @return [boolean] verify result.
    def verify(digest, sign, value, base64_decode=true)

      # not private, return false.
      return false unless @rsa.private?

      # base64 decode.
      if base64_decode
        sign = decode_base64(sign)
      end
      @rsa.verify(digest, sign, value)
    end

    # save one file key.
    # @param [String] file_path save file path. absolute.
    # @param [integer] mode pem or der.
    # @param [OpenSSL::Cipher] cipher cipher instance.
    # @param [String] pass password
    def to_one_file(file_path, mode, cipher=nil, pass=nil)

      save_key_pair = key_pair(mode, cipher, pass)

      # save file.
      OsslRsa::FileOp.save_one_file(file_path, save_key_pair, mode)
    end

    # save file key.
    # filename is [private.xxx(pem or der)], [public.xxx(pem or der)]
    # @param [String] dir_path save dir path. absolute.
    # @param [integer] mode pem or der.
    # @param [OpenSSL::Cipher] cipher cipher instance.
    # @param [String] pass password
    # @param [boolean] add_now add now date string flag.
    # @return [Hash] save file path pair. xxx[:private] = private file path, xxx[:public] = public file path.
    def to_file(dir_path, mode, cipher=nil, pass=nil, add_now=false)

      save_key_pair = key_pair(mode, cipher, pass)

      # save file.
      save_path_pair = OsslRsa::FileOp.save(dir_path, save_key_pair, mode, add_now)
      save_path_pair
    end

    # save file key.
    # @param [Hash] file_path_pair save file path pair. xxx[:private] = private file path, xxx[:public] = public file path.
    # @param [integer] mode pem or der.
    # @param [OpenSSL::Cipher] cipher cipher instance.
    # @param [String] pass password
    # @return [Hash] save file path pair. xxx[:private] = private file path, xxx[:public] = public file path.
    def to_specify_file(file_path_pair, mode, cipher=nil, pass=nil)

      save_key_pair = key_pair(mode, cipher, pass)

      # save file.
      save_path_pair = OsslRsa::FileOp.save_file(save_key_pair, file_path_pair, mode)
      save_path_pair
    end

    # private check.
    # @return [boolean] OpsnSSL::PKey::RSA.private?
    def private?
      @rsa.private?
    end

    # public check.
    # @return [boolean] OpenSSL::PKey::RSA.public?
    def public?
      @rsa.public?
    end

    # get private and public key.
    # private key set self OpenSSL::PKey::RSA instance.
    # @param [integer] mode pem or der.
    # @param [OpenSSL::Cipher] cipher cipher instance.
    # @param [String] pass password
    # @return [Hash] key pair hash. xx[:private] = private_key, xx[:public] = public_key
    def key_pair(mode, cipher=nil, pass=nil)

      private_key = get_private_key(mode, cipher, pass)
      public_key = get_public_key(mode, cipher, pass)

      { private: private_key, public: public_key }
    end

    # get private and public key text.
    # @return [Hash] key pair hash. xx[:private] = private_key, xx[:public] = public_key
    def text_pair

      private_key = @rsa.to_text if @rsa.private?
      public_key = @rsa.public_key.to_text if @rsa.public?

      { private: private_key, public: public_key }
    end

    # set base64 rfc.
    # @param [integer] rfc rfc
    def set_rfc(rfc)
      @rfc = rfc
    end

    # get rsa instance.
    # @return [OpenSSL::PKey::RSA] rsa instance.
    def rsa
      @rsa
    end

    private

    # get private key.
    # @param [integer] mode pem or der.
    # @param [OpenSSL::Cipher] cipher cipher instance.
    # @param [String] pass password
    # @return [String] pem or der private key.
    def get_private_key(mode, cipher, pass)

      # if not have private_key, return nil
      return nil unless @rsa.private?

      cv_key = convert_key(mode, @rsa, cipher, pass)
      cv_key
    end

    # get public key.
    # @param [integer] mode pem or der.
    # @param [OpenSSL::Cipher] cipher cipher instance.
    # @param [String] pass password
    # @return [String] pem or der public key.
    def get_public_key(mode, cipher, pass)

      # if not have public_key, return nil
      return nil unless @rsa.public?

      cv_key = convert_key(mode, @rsa.public_key, cipher, pass)
      cv_key
    end

    # convert key to pem or der.
    # @param [integer] mode pem or der.
    # @param [OpsnSSL::PKey::RSA] key rsa key.
    # @param [OpenSSL::Cipher] cipher cipher instance.
    # @param [String] pass password
    # @return [String] pem or der key.
    def convert_key(mode, key, cipher, pass)
      
      cv_key = nil
      # convert key.
      if mode == PEM
        cv_key = key.to_pem(cipher, pass)
      elsif mode == DER
        cv_key = key.to_der
      end

      cv_key
    end

    # encode base64.
    # @param [String] value target value.
    # @return [String] base64 encode value.
    def encode_base64(value)

      if @rfc == RFC2045
        Base64.encode64(value)
      elsif @rfc == RFC4648
        Base64.strict_encode64(value)
      else
        Base64.encode64(value)
      end
    end

    # decode base64.
    # @param [String] value target value.
    # @return [String] base64 decode value.
    def decode_base64(value)

      if @rfc == RFC2045
        Base64.decode64(value)
      elsif @rfc == RFC4648
        Base64.strict_decode64(value)
      else
        Base64.decode64(value)
      end
    end
  end
end
