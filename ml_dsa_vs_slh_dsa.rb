require 'openssl'

puts "Ruby OpenSSL #{OpenSSL::VERSION}: #{OpenSSL::OPENSSL_LIBRARY_VERSION}"

ml_dsa = OpenSSL::PKey.generate_key('ML-DSA-44')
slh_dsa = OpenSSL::PKey.generate_key('SLH-DSA-SHA2-128f')

puts "ML-DSA:  #{ml_dsa.inspect}"
puts "SLH-DSA: #{slh_dsa.inspect}"

# seed param
seed = ml_dsa.get_param('seed')
puts "ML-DSA  get_param('seed'): #{seed.bytesize} bytes"
begin
  slh_dsa.get_param('seed')
  puts "SLH-DSA get_param('seed'): OK (unexpected)"
rescue OpenSSL::PKey::PKeyError => e
  puts "SLH-DSA get_param('seed'): raised #{e.class} - #{e.message}"
end

# mu param
mu_value = "\x00" * 64
sig_mu = ml_dsa.sign(nil, mu_value, { "mu" => "1" })
puts "ML-DSA  sign with mu=1: sig size=#{sig_mu.bytesize}"
data = "test message"
begin
  slh_dsa.sign(nil, data, { "mu" => "1" })
  puts "SLH-DSA sign with mu=1: OK (unexpected)"
rescue OpenSSL::PKey::PKeyError => e
  puts "SLH-DSA sign with mu=1: #{e.class} - #{e.message}"
end
