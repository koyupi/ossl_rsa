require "openssl"

# openssl rsa module.
module OsslRsa

  # generator class
  class Generator

    # generate OpenSSL::PKey::RSA instance.
    # generate rsa instance by options.
    # options[:size] : key size
    # options[:obj] : pem or der
    # options[:pass] : password
    # @param [Hash] options generate options.
    # @return [OpenSSL::PKey::RSA] rsa instance.
    def self.generate(options)

      rsa = nil
      # if size and private exist, raise error.
      if (!options[:size].nil? && !options[:obj].nil?)
        raise OpenSSL::PKey::RSAError.new("size and obj is nil.")
      end

      # if exist size, generate use size, cipher.
      unless options[:size].nil?
        rsa = generate_rsa_by_size(options[:size])
      end

      # if exist obj, generate use obj, pass.
      unless options[:obj].nil?
        rsa = generate_rsa_by_key(options[:obj], options[:pass])
      end

      # raise Error
      if rsa.nil?
        raise OpenSSL::PKey::RSAError.new("fail create rsa instance.")
      end

      rsa
    end

    private

    # generate rsa.
    # @param [integer] size key size.
    # @return [OpenSSL::PKey::RSA] rsa instance.
    def self.generate_rsa_by_size(size)

      # add seed.
      OpenSSL::Random.seed(SecureRandom.hex(8))
      # generate rsa instance.
      rsa = OpenSSL::PKey::RSA.new(size)
      rsa
    end

    # generate rsa.
    # @param [String] pem / der.
    # @param [String] pass password
    # @return [OpenSSL::PKey::RSA] rsa instance.
    def self.generate_rsa_by_key(obj, pass=nil)

      rsa = OpenSSL::PKey::RSA.new(obj, pass)
      rsa
    end
  end
end