require 'spec_helper'
require 'openssl'

describe OsslRsa::Rsa do

  let(:pem_private) { "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,DE2E6EAB0EBD48D64311896C7E809096\n\nCj555Q9vDZkRD205nBKvf1C2/kx4I1wI5bz18/tLlf230AykNJF7pE7oIMP550tO\nt5lMFYqZ/66+0bI6MFgjslcQinX6EWdrqdU7MfmL63zv2kvsStOORrP8bo0qIeHx\nHU0lnMhrjM/4990OvBM+ePe2Z6JxfjAumjQ5zHQjN8nODJp0SRuwjUBIj1oM8bea\nod2c9WlH1XlyOaJ7kHYw1wOObCCNLEKVSj+6N80Ju38jXLqJrXtRiZucvRJ/EEpk\nN0v1ZrzkLB2p1l1KYJbrp0n7NL+acoOBM4QmKd9x/5BRZQqMFcFwCxAsgx4dqMKC\nVfbNcCNx0i9xuhOuYJDs9K3k/60zfYBLbDVkswmJv/RTkMrq8/l/gDCu3NQ1tZhZ\nzLuG+DZWdDCPRFvBd27p/5aQlxtqDp1HgxYXS/OHdVdO9b4A4V0PFZ0wKPE4PfqB\nPiEwnL78M+/rvoiZHCsUQKWOGOZIfFosCsJYKAI3e0QYliBdjiuhrX/vRjjzQlZs\ni5h5VB3UvXsWnt8KOreaH628+hOjpxMGZ4zmnL+7SfF1cf0ynyOwJEUaoHEt1PH6\nXQzsMJdJuogFypZeX9IkpcD2Buo5piTRX2OyhFR+HSSEbAsEPs/EVQwH3WXbQLnw\ndYXoN2rt9JSEoqCJvvqVBq5gdZWdFB1nIzAIKb4mTA/Sv376iuLwUpPmOkraTYm4\nX30n1so0s8nGk/SkDOZC78MOLZvtpd5kaMwQ08JHusAy2rxft4RlJfdCuaLvBCsV\nEyz3vmSC/Qe3DI4k4ZIJafr/H/5fZ+B9Nc0cyTYBmgGlSd+INZUYk/pPxC7jjfk2\n78sjjxZPJKFICBKD9xiJas0V8iplgo31dtc2/jdOfsd/82+XH8Wrb9WFfs1f63TD\n+YZfqNqMxNY+R3YW6rYy1w5s7eOTJSehtVkZhkJ7lvMr8vQ4yrvg0BvqZFPugSBv\ny+jqaddNDHBtej3SGjhfQPeGrj7YpEvOgNqjSpLs0YImeQbnPewfUNrUdQAcwYNX\nqNIPPxGWl5NAJKF/ivhJor+SJuU8LBpN0xI2tYGUQq3XxeaFPSh+jWDilv/QGf5n\noRhOS6EE3i3dyyr4mba2p/52rFV3uNY3bi/xFSZKmOsQ+LfMMgvZR7f9QuXm2t2K\nnp0m/FivHxVBOHnJP1S6k69fUtXf5e0oi0BK6nJE9vk0qrlDLIGa67TMclf2kHGG\nWZPpd1GFvWOK6K3fJg5Z/hEJl9RPgnfmYg0lDEgOXNC0WKTnsjIG6aRlo4/bEgn3\nKyjik2gjssZ0EnYjx2gMXnqSxoAtRcQ4vUUUqJvxec/2O+B5jeBcOJcuKFdNkEeX\ngoveUpvVcdNuSiKrcMIyn0GWkTRwgr0E31nSC7hd9/bCjUaJuEqKHM0nFHOYloue\n8hcN+r62HNQZKjeQ+WynpdYNiiPot0p8+2SItAVJ/o5XaxEFWIh8fBic77rYMNXz\nAZTl91IX8V5BwELHYAaHizBX4bB6f6wovN9je+RrKPIbr+UuqaKPwxIuiM7SFycV\ngXOUPj5mllEkv1WPLX3dlYlvUBrrQFWvA7LPUI9opiyHfW6w12XDfZkHC0yJENyM\n-----END RSA PRIVATE KEY-----" }
  let(:pem_public) { "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAolzkExP37u5c43Lr5mxM\nxP4bMBhwSfGytAIjbTJRtWnRhlIbDwPoKHCDq/8HtSVTkjv9t/eLod7RdWoAqsCA\naMY7wgrbgH7jl78kdY4OuZZjJssMk7xAXkVWA0FA3KElil7f9ye1CvrayT3Uzpp+\ncJEXXi1+I6Tkz0v/6zG+WV6JB0o9JWrNOGdbbjy9TeGE21u1QMW4gYD7FpkJ6PFa\nVC+14djol8cEHAVSZTGnLXIS5jO1MQ/G1qxPkvX+HBpjzp40/AW1QsBVbTkwLyYd\n6J2DMlOAzwxHQFcY2VXFZxMwQ1tyCG0EMINPAxSOoZ6E66xehJwfam4vUS10xq3T\nOQIDAQAB\n-----END PUBLIC KEY-----" }
  let(:sign_value) { "b2zRCpulqpRwamjvOpN4j4VJVIfQHuoeIo86/rk2edAw1Xghjy5dTch/bbE8\naIUhxGDDKKTV+WBL9DUROTQ1GXE39I5P3UbW8nw5I3qro0U8uHm8WU0pTGYe\nyLyUC9KE3KSLebJtADmA1WXM/2Qen4u72R/EQEln3KvHUQGbBzAahyowJJj3\nmQ0i75nuck9LdSts1vkGLWd5V79faNm/E5MA7QjsCpRa7RID5bl2rOtpT88n\nJpw2FdIl3Tj7Nt3S0bwDqzwMSuiHDNMSfZknB1nOCO3Z4k1mAbu2KHaj4p49\nl0RkNbDNKkMGoIbx5Sh5qNvZwCSDzmuiTbHVaFK9og==" }
  let(:value) { "rsa encrypt value" }
  let(:dir_path) { 'C:\GitHub' }
  let(:pem_file_path_pair) { { private: 'C:\GitHub\private.pem', public: 'C:\GitHub\public.pem'} }
  let(:der_file_path_pair) { { private: 'C:\GitHub\private.der', public: 'C:\GitHub\public.der'} }

  it 'pem test' do
    rsa = OsslRsa::Rsa.new({size: 2048})
    key_pair = rsa.key_pair(OsslRsa::PEM)
    # puts key_pair[:private]
    # puts key_pair[:public]
    expect(key_pair).to be_truthy
  end

  it 'pem cipher pass test' do
    rsa = OsslRsa::Rsa.new({size: 2048})
    key_pair = rsa.key_pair(OsslRsa::PEM, OpenSSL::Cipher.new("AES-256-CBC"), "ossl_rsa")
    # puts key_pair[:private]
    # puts key_pair[:public]
    expect(key_pair).to be_truthy
  end

  it 'der test' do
    rsa = OsslRsa::Rsa.new({size: 2048})
    key_pair = rsa.key_pair(OsslRsa::DER)
    # puts key_pair[:private]
    # puts key_pair[:public]
    expect(key_pair).to be_truthy
  end

  it 'der cipher pass tests' do
    rsa = OsslRsa::Rsa.new({size: 2048})
    key_pair = rsa.key_pair(OsslRsa::DER, OpenSSL::Cipher.new("DES"), "ossl_rsa")
    # puts key_pair[:private]
    # puts key_pair[:public]
    expect(key_pair).to be_truthy
  end

  it 'encrypt test' do
    rsa = OsslRsa::Rsa.new({size: 2048})
    enc_value = rsa.encrypt(value)
    # puts enc_value
    expect(enc_value).to be_truthy
  end

  it 'decrypt test' do
    rsa = OsslRsa::Rsa.new({size: 2048})
    enc_value = rsa.encrypt(value)
    # puts enc_value
    expect(enc_value).not_to eq value
    dec_value = rsa.decrypt(enc_value)
    # puts dec_value
    expect(dec_value).to eq value
  end

  it 'from pem private test' do
    rsa = OsslRsa::Rsa.new({obj: pem_private, pass: "ossl_rsa"})
    key_pair = rsa.key_pair(OsslRsa::PEM)
    # puts key_pair[:private]
    # puts key_pair[:public]
    expect(rsa.private?).to be_truthy
    expect(rsa.public?).to be_truthy
    expect(key_pair).to be_truthy
  end

  it 'from pem public test' do
    rsa = OsslRsa::Rsa.new({obj: pem_public, pass: "ossl_rsa"})
    key_pair = rsa.key_pair(OsslRsa::PEM)
    expect(key_pair[:private]).to be_falsey
    # puts key_pair[:public]
    expect(key_pair).to be_truthy
  end

  it 'from pem private test no pass' do
    rsa = OsslRsa::Rsa.new({obj: pem_private})
    key_pair = rsa.key_pair(OsslRsa::PEM)
    # puts key_pair[:private]
    # puts key_pair[:public]
    # pass phrase = ossl_rsa
    expect(key_pair).to be_truthy
  end

  it 'from pem public test' do
    rsa = OsslRsa::Rsa.new({obj: pem_public, pass: "ossl_rsa"})
    key_pair = rsa.key_pair(OsslRsa::PEM)
    expect(key_pair[:private]).to be_falsey
    # puts key_pair[:public]
    expect(rsa.private?).to be_falsey
    expect(rsa.public?).to be_truthy
    expect(key_pair).to be_truthy
  end

  it 'text test' do
    rsa = OsslRsa::Rsa.new({size: 2048})
    text_pair = rsa.text_pair
    # puts text_pair[:private]
    # puts text_pair[:public]
    expect(text_pair[:private]).to be_truthy
    expect(text_pair[:public]).to be_truthy
  end

  it 'text public only test' do
    rsa = OsslRsa::Rsa.new({obj: pem_public, pass: "ossl_rsa"})
    text_pair = rsa.text_pair
    # puts text_pair[:private]
    # puts text_pair[:public]
    expect(text_pair[:private]).to be_falsey
    expect(text_pair[:public]).to be_truthy
  end

  it 'public only decrypt test' do
    rsa = OsslRsa::Rsa.new({obj: pem_public, pass: "ossl_rsa"})
    enc_value = rsa.decrypt(value)
    expect(enc_value).to be_falsey
  end

  it 'sign test' do
    rsa = OsslRsa::Rsa.new({obj: pem_private, pass: "ossl_rsa"})
    sign_value = rsa.sign("sha256", value)
    # puts sign_value
    expect(sign_value).to be_truthy
  end

  it 'verify test false' do
    rsa = OsslRsa::Rsa.new({obj: pem_private, pass: "ossl_rsa"})
    expect(rsa.verify("md5", sign_value, value)).to be_falsey
  end

  it 'verify test true' do
    rsa = OsslRsa::Rsa.new({obj: pem_private, pass: "ossl_rsa"})
    expect(rsa.verify("sha256", sign_value, value)).to be_truthy
  end

  it 'pem file write test' do
    rsa = OsslRsa::Rsa.new({size: 2048})
    key_pair = rsa.key_pair(OsslRsa::PEM)
    file_path_pair = rsa.to_file(dir_path, OsslRsa::PEM)
    expect(File.exist?(file_path_pair[:private])).to be_truthy
    expect(File.exist?(file_path_pair[:public])).to be_truthy

    private_contesnts = File.read(file_path_pair[:private])
    expect(private_contesnts).to eq key_pair[:private]
    public_contesnts = File.read(file_path_pair[:public])
    expect(public_contesnts).to eq key_pair[:public]

    File.delete(file_path_pair[:private])
    File.delete(file_path_pair[:public])
  end

  it 'der file write test' do
    rsa = OsslRsa::Rsa.new({size: 2048})
    key_pair = rsa.key_pair(OsslRsa::DER)
    file_path_pair = rsa.to_file(dir_path, OsslRsa::DER)
    expect(File.exist?(file_path_pair[:private])).to be_truthy
    expect(File.exist?(file_path_pair[:public])).to be_truthy

    private_file = File.open(file_path_pair[:private], "rb")
    expect(private_file.read).to eq key_pair[:private]
    private_file.close
    public_file = File.open(file_path_pair[:public], "rb")
    expect(public_file.read).to eq key_pair[:public]
    public_file.close

    File.delete(file_path_pair[:private])
    File.delete(file_path_pair[:public])
  end

  it 'pem specify file write test' do
    rsa = OsslRsa::Rsa.new({size: 2048})
    key_pair = rsa.key_pair(OsslRsa::PEM)
    file_path_pair = rsa.to_specify_file(pem_file_path_pair, OsslRsa::PEM)
    expect(File.exist?(file_path_pair[:private])).to be_truthy
    expect(File.exist?(file_path_pair[:public])).to be_truthy

    private_contesnts = File.read(file_path_pair[:private])
    expect(private_contesnts).to eq key_pair[:private]
    public_contesnts = File.read(file_path_pair[:public])
    expect(public_contesnts).to eq key_pair[:public]

    File.delete(file_path_pair[:private])
    File.delete(file_path_pair[:public])
  end

  it 'der specify file write test' do
    rsa = OsslRsa::Rsa.new({size: 2048})
    key_pair = rsa.key_pair(OsslRsa::DER)
    file_path_pair = rsa.to_specify_file(der_file_path_pair, OsslRsa::DER)
    expect(File.exist?(file_path_pair[:private])).to be_truthy
    expect(File.exist?(file_path_pair[:public])).to be_truthy

    private_file = File.open(file_path_pair[:private], "rb")
    expect(private_file.read).to eq key_pair[:private]
    private_file.close
    public_file = File.open(file_path_pair[:public], "rb")
    expect(public_file.read).to eq key_pair[:public]
    public_file.close

    File.delete(file_path_pair[:private])
    File.delete(file_path_pair[:public])
  end

  it 'rsa test' do
    rsa = OsslRsa::Rsa.new({obj: pem_public, pass: "ossl_rsa"})
    actual_ras = rsa.rsa
    # puts actual_ras.to_pem
    expect(actual_ras).to be_truthy
  end
end
