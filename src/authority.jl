# The manager as an ephemeral certificate authority (PROTOCOL.md §1, §11b): one in-memory CA per manager, issuing
# certificates to the manager itself and to its proxies. Both ends of a TLS connection require the other's certificate
# to chain to it; the common name carries the peer's id, which is what the connector verifies. Nothing touches the disk.
# Shapes follow the Python reference: EC P-256 keys, 366 days from five minutes before issue, the CA with path length
# 0 and the certificate-signing key usages, leaves with server and client extended key usage and the common name as a
# DNS subject alternative name (plus any IP addresses given).

const CERTIFICATE_LIFETIME = 366 * 86400

mutable struct Authority
    name::String
    key::OpenSSL.EvpPKey
    cert::OpenSSL.X509Certificate
    ca_pem::String
end

ec_key() = OpenSSL.EvpPKey(OpenSSL.ec_generate_key("prime256v1"))

function pem_certificate(cert::OpenSSL.X509Certificate)
    io = IOBuffer()
    write(io, cert)
    return String(take!(io))
end

"""The PEM of a private key (PKCS#8, `BEGIN PRIVATE KEY`, as the Python reference writes it)."""
function pem_private_key(key::OpenSSL.EvpPKey)
    bio = OpenSSL.BIO(OpenSSL.BIOMethodMemory())
    ccall((:PEM_write_bio_PrivateKey, libcrypto), Cint,
          (OpenSSL.BIO, OpenSSL.EvpPKey, Ptr{Cvoid}, Ptr{Cvoid}, Cint, Ptr{Cvoid}, Ptr{Cvoid}),
          bio, key, C_NULL, C_NULL, 0, C_NULL, C_NULL) == 1 || error(openssl_error_text("PEM_write_bio_PrivateKey failed"))
    return String(copy(OpenSSL.bio_get_mem_data(bio)))
end

"""The certificate as `openssl x509 -text` prints it (for diagnostics and tests)."""
function certificate_text(cert::OpenSSL.X509Certificate)
    bio = OpenSSL.BIO(OpenSSL.BIOMethodMemory())
    ccall((:X509_print, libcrypto), Cint, (OpenSSL.BIO, OpenSSL.X509Certificate), bio, cert) == 1 ||
        error(openssl_error_text("X509_print failed"))
    return String(copy(OpenSSL.bio_get_mem_data(bio)))
end
certificate_text(pem::AbstractString) = certificate_text(OpenSSL.X509Certificate(String(pem)))

function set_serial!(cert::OpenSSL.X509Certificate)
    serial = ccall((:X509_get_serialNumber, libcrypto), Ptr{Cvoid}, (OpenSSL.X509Certificate,), cert)
    ccall((:ASN1_INTEGER_set, libcrypto), Cint, (Ptr{Cvoid}, Clong), serial, rand(Clong(1):typemax(Clong))) == 1 ||
        error(openssl_error_text("ASN1_INTEGER_set failed"))
    return
end

"""A certificate skeleton: X.509 v3, the subject, validity from five minutes ago, a random serial."""
function certificate_for(common_name::AbstractString, key::OpenSSL.EvpPKey)
    cert = OpenSSL.X509Certificate()
    cert.version = 2
    name = OpenSSL.X509Name()
    OpenSSL.add_entry(name, "CN", String(common_name))
    cert.subject_name = name
    now = round(Int, time())
    cert.time_not_before = OpenSSL.Asn1Time(now - 300)
    cert.time_not_after = OpenSSL.Asn1Time(now + CERTIFICATE_LIFETIME)
    cert.public_key = key
    set_serial!(cert)
    return cert
end

"""
    Authority(name="protocol-proxy manager")

A CA named `name`: an EC P-256 key and a self-signed certificate with the CA basic constraint (path length 0) and the
certificate-signing key usages, as the Python reference issues them.
"""
function Authority(name::AbstractString="protocol-proxy manager")
    key = ec_key()
    cert = certificate_for(name, key)
    cert.issuer_name = cert.subject_name
    OpenSSL.add_extension(cert, OpenSSL.X509Extension("basicConstraints", "critical,CA:TRUE,pathlen:0"))
    OpenSSL.add_extension(cert, OpenSSL.X509Extension("keyUsage", "critical,digitalSignature,keyCertSign,cRLSign"))
    OpenSSL.sign_certificate(cert, key)
    return Authority(String(name), key, cert, pem_certificate(cert))
end

function is_ip_address(s::AbstractString)
    try
        parse(IPAddr, s)
        return true
    catch
        return false
    end
end

"""
    issue(authority, common_name; ip_addresses=[]) -> TlsMaterial

A certificate and key for one end: `common_name` is the peer's id (hex); `ip_addresses` become IP subject alternative
names (an unparsable address becomes a DNS name, as in Python). Usable as server and client.
"""
function issue(a::Authority, common_name::AbstractString; ip_addresses::AbstractVector{<:AbstractString}=String[])
    key = ec_key()
    cert = certificate_for(common_name, key)
    cert.issuer_name = a.cert.subject_name
    OpenSSL.add_extension(cert, OpenSSL.X509Extension("basicConstraints", "critical,CA:FALSE"))
    OpenSSL.add_extension(cert, OpenSSL.X509Extension("extendedKeyUsage", "serverAuth,clientAuth"))
    alt = ["DNS:" * String(common_name)]
    for address in ip_addresses
        push!(alt, (is_ip_address(address) ? "IP:" : "DNS:") * String(address))
    end
    OpenSSL.add_extension(cert, OpenSSL.X509Extension("subjectAltName", join(alt, ",")))
    OpenSSL.sign_certificate(cert, a.key)
    return TlsMaterial(a.ca_pem, pem_certificate(cert), pem_private_key(key))
end
