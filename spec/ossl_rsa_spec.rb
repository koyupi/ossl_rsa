require 'spec_helper'
require 'openssl'

describe OsslRsa do

  it 'has a version number' do
    expect(OsslRsa::VERSION).not_to be nil
  end
end