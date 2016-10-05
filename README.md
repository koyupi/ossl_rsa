# OsslRsa

Welcome to your new gem! In this directory, you'll find the files you need to be able to package up your Ruby library into a gem. Put your Ruby code in the file `lib/ossl_rsa`. To experiment with that code, run `bin/console` for an interactive prompt.

This gem provide RSA encryption and sign, verify by openssl lib.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'ossl_rsa'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install ossl_rsa

## Usage

Encrypt and decrypt sample.

```ruby
require 'ossl_rsa'

rsa = OsslRsa::Rsa.new({size: 2048})
enc_value = rsa.encrypt("encrypt value")
puts enc_value

dec_value = rsa.decrypt(enc_value)
puts dec_value
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/koyupi/ossl_rsa. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](contributor-covenant.org) code of conduct.


## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

