require 'spec_helper'
require 'openssl'

describe OsslRsa::Generator do

  let(:pem_private) { "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,DE2E6EAB0EBD48D64311896C7E809096\n\nCj555Q9vDZkRD205nBKvf1C2/kx4I1wI5bz18/tLlf230AykNJF7pE7oIMP550tO\nt5lMFYqZ/66+0bI6MFgjslcQinX6EWdrqdU7MfmL63zv2kvsStOORrP8bo0qIeHx\nHU0lnMhrjM/4990OvBM+ePe2Z6JxfjAumjQ5zHQjN8nODJp0SRuwjUBIj1oM8bea\nod2c9WlH1XlyOaJ7kHYw1wOObCCNLEKVSj+6N80Ju38jXLqJrXtRiZucvRJ/EEpk\nN0v1ZrzkLB2p1l1KYJbrp0n7NL+acoOBM4QmKd9x/5BRZQqMFcFwCxAsgx4dqMKC\nVfbNcCNx0i9xuhOuYJDs9K3k/60zfYBLbDVkswmJv/RTkMrq8/l/gDCu3NQ1tZhZ\nzLuG+DZWdDCPRFvBd27p/5aQlxtqDp1HgxYXS/OHdVdO9b4A4V0PFZ0wKPE4PfqB\nPiEwnL78M+/rvoiZHCsUQKWOGOZIfFosCsJYKAI3e0QYliBdjiuhrX/vRjjzQlZs\ni5h5VB3UvXsWnt8KOreaH628+hOjpxMGZ4zmnL+7SfF1cf0ynyOwJEUaoHEt1PH6\nXQzsMJdJuogFypZeX9IkpcD2Buo5piTRX2OyhFR+HSSEbAsEPs/EVQwH3WXbQLnw\ndYXoN2rt9JSEoqCJvvqVBq5gdZWdFB1nIzAIKb4mTA/Sv376iuLwUpPmOkraTYm4\nX30n1so0s8nGk/SkDOZC78MOLZvtpd5kaMwQ08JHusAy2rxft4RlJfdCuaLvBCsV\nEyz3vmSC/Qe3DI4k4ZIJafr/H/5fZ+B9Nc0cyTYBmgGlSd+INZUYk/pPxC7jjfk2\n78sjjxZPJKFICBKD9xiJas0V8iplgo31dtc2/jdOfsd/82+XH8Wrb9WFfs1f63TD\n+YZfqNqMxNY+R3YW6rYy1w5s7eOTJSehtVkZhkJ7lvMr8vQ4yrvg0BvqZFPugSBv\ny+jqaddNDHBtej3SGjhfQPeGrj7YpEvOgNqjSpLs0YImeQbnPewfUNrUdQAcwYNX\nqNIPPxGWl5NAJKF/ivhJor+SJuU8LBpN0xI2tYGUQq3XxeaFPSh+jWDilv/QGf5n\noRhOS6EE3i3dyyr4mba2p/52rFV3uNY3bi/xFSZKmOsQ+LfMMgvZR7f9QuXm2t2K\nnp0m/FivHxVBOHnJP1S6k69fUtXf5e0oi0BK6nJE9vk0qrlDLIGa67TMclf2kHGG\nWZPpd1GFvWOK6K3fJg5Z/hEJl9RPgnfmYg0lDEgOXNC0WKTnsjIG6aRlo4/bEgn3\nKyjik2gjssZ0EnYjx2gMXnqSxoAtRcQ4vUUUqJvxec/2O+B5jeBcOJcuKFdNkEeX\ngoveUpvVcdNuSiKrcMIyn0GWkTRwgr0E31nSC7hd9/bCjUaJuEqKHM0nFHOYloue\n8hcN+r62HNQZKjeQ+WynpdYNiiPot0p8+2SItAVJ/o5XaxEFWIh8fBic77rYMNXz\nAZTl91IX8V5BwELHYAaHizBX4bB6f6wovN9je+RrKPIbr+UuqaKPwxIuiM7SFycV\ngXOUPj5mllEkv1WPLX3dlYlvUBrrQFWvA7LPUI9opiyHfW6w12XDfZkHC0yJENyM\n-----END RSA PRIVATE KEY-----" }
  let(:pem_public) { "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAolzkExP37u5c43Lr5mxM\nxP4bMBhwSfGytAIjbTJRtWnRhlIbDwPoKHCDq/8HtSVTkjv9t/eLod7RdWoAqsCA\naMY7wgrbgH7jl78kdY4OuZZjJssMk7xAXkVWA0FA3KElil7f9ye1CvrayT3Uzpp+\ncJEXXi1+I6Tkz0v/6zG+WV6JB0o9JWrNOGdbbjy9TeGE21u1QMW4gYD7FpkJ6PFa\nVC+14djol8cEHAVSZTGnLXIS5jO1MQ/G1qxPkvX+HBpjzp40/AW1QsBVbTkwLyYd\n6J2DMlOAzwxHQFcY2VXFZxMwQ1tyCG0EMINPAxSOoZ6E66xehJwfam4vUS10xq3T\nOQIDAQAB\n-----END PUBLIC KEY-----" }
  
  it 'size test' do
    rsa = OsslRsa::Rsa.new({size: 2048})
    expect(rsa).to be_truthy
  end

  it 'private pem test' do
    rsa = OsslRsa::Rsa.new({obj: pem_private, pass: "ossl_rsa"})
    expect(rsa).to be_truthy
  end

  it 'public pem test' do
    rsa = OsslRsa::Rsa.new({obj: pem_public, pass: "ossl_rsa"})
    expect(rsa).to be_truthy
  end

  it 'fail test' do
    expect { rsa = OsslRsa::Rsa.new() }.to raise_error(OpenSSL::PKey::RSAError)
  end
end