# The contents of this file are subject to the terms
# of the Common Development and Distribution License
# (the License). You may not use this file except in
# compliance with the License.
#
# You can obtain a copy of the License at
# https://opensso.dev.java.net/public/CDDLv1.0.html or
# opensso/legal/CDDLv1.0.txt
# See the License for the specific language governing
# permission and limitations under the License.
#
# When distributing Covered Code, include this CDDL
# Header Notice in each file and include the License file
# at opensso/legal/CDDLv1.0.txt.
# If applicable, add the following below the CDDL Header,
# with the fields enclosed by brackets [] replaced by
# your own identifying information:
# "Portions Copyrighted [year] [name of copyright owner]"
#
# $Id: xml_sec.rb,v 1.6 2007/10/24 00:28:41 todddd Exp $
#
# Copyright 2007 Sun Microsystems Inc. All Rights Reserved
# Portions Copyrighted 2007 Todd W Saxton.

require 'rubygems'
require "rexml/document"
require "rexml/xpath"
require "openssl"
require 'nokogiri'
require "digest/sha1"
require "digest/sha2"
require "onelogin/ruby-saml/validation_error"

module XMLSecurity

  class BaseDocument < REXML::Document
    C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
    DSIG = "http://www.w3.org/2000/09/xmldsig#"

    def canon_algorithm(element)
      case element
      when "http://www.w3.org/2001/10/xml-exc-c14n#"
        Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0
      when "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        Nokogiri::XML::XML_C14N_1_0
      when "http://www.w3.org/2006/12/xml-c14n11"
        Nokogiri::XML::XML_C14N_1_1
      else
        Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0
      end
    end

    def algorithm(element)
      case element[/(?:rsa\-)?sha(.*?)$/i, 1]
      when "256" then OpenSSL::Digest::SHA256
      when "384" then OpenSSL::Digest::SHA384
      when "512" then OpenSSL::Digest::SHA512
      else
        OpenSSL::Digest::SHA1
      end
    end

    private

    def nokogiri_document
      @nokogiri_document ||= nokogiri_parse(self.to_s)
    end

    def nokogiri_parse(xml)
      Nokogiri::XML(xml) { |config| config.noent.nonet }
    end

    def algorithm_value(element)
      element && element.attribute("Algorithm").value
    end
  end

  class Document < BaseDocument
    RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
    RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
    RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
    SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1"
    SHA256 = "http://www.w3.org/2001/04/xmldsig-more#sha256"
    SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
    SHA512 = "http://www.w3.org/2001/04/xmldsig-more#sha512"
    ENVELOPED_SIG = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
    INC_PREFIX_LIST = "#default samlp saml ds xs xsi md"

    attr_writer :uuid

    def uuid
      @uuid ||= nokogiri_document.root.attributes['ID']
    end

    # <Signature>
    #   <SignedInfo>
    #     <CanonicalizationMethod />
    #     <SignatureMethod />
    #     <Reference>
    #        <Transforms>
    #        <DigestMethod>
    #        <DigestValue>
    #     </Reference>
    #     <Reference /> etc.
    #   </SignedInfo>
    #   <SignatureValue />
    #   <KeyInfo />
    #   <Object />
    # </Signature>
    def sign_document(private_key, certificate, signature_method = RSA_SHA1, digest_method = SHA1)
      signature_element = REXML::Element.new("ds:Signature")
      signature_element.add_namespace("ds", DSIG)

      # add SignedInfo
      signature_element.add_element signed_info_element(
        signature_method,
        digest_method
      )

      # add SignatureValue
      signature_element.add_element("ds:SignatureValue").text = signature_value(
        private_key,
        signature_method,
        signature_element
      )

      # add KeyInfo
      signature_element.add_element key_info_element(certificate)

      # insert the signature
      if issuer_element = self.elements["//saml:Issuer"]
        self.root.insert_after issuer_element, signature_element
      else
        if sp_sso_descriptor = self.elements["/md:EntityDescriptor"]
          self.root.insert_before sp_sso_descriptor, signature_element
        else
          self.root.add_element(signature_element)
        end
      end
    end

    protected

    def signed_info_element(signature_method, digest_method)
      canonical_document = nokogiri_document.canonicalize(
        canon_algorithm(C14N),
        INC_PREFIX_LIST.split(" ")
      )
      digest_value = encoded_digest(
        canonical_document,
        algorithm(digest_method)
      )

      builder = Nokogiri::XML::Builder.new do |xml|
        xml["ds"].SignedInfo("xmlns:ds" => DSIG) do
          xml.CanonicalizationMethod("Algorithm" => C14N)
          xml.SignatureMethod("Algorithm" => signature_method)
          xml.Reference("URI" => "##{uuid}") do
            xml.Transforms do
              xml.Transform("Algorithm" => ENVELOPED_SIG)
              xml.Transform("Algorithm" => C14N) do
                xml["ec"].InclusiveNamespaces(
                  "xmlns:ec" => C14N,
                  "PrefixList" => INC_PREFIX_LIST
                )
              end
            end
            xml.DigestMethod("Algorithm" => digest_method)
            xml.DigestValue digest_value
          end
        end
      end

      REXML::Document.new(builder.doc.to_xml).elements["//ds:SignedInfo"]
    end

    def key_info_element(certificate)
      builder = Nokogiri::XML::Builder.new do |xml|
        xml["ds"].KeyInfo("xmlns:ds" => DSIG) do
          xml.X509Data do
            xml.X509Certificate encoded_certificate(certificate)
          end
        end
      end

      REXML::Document.new(builder.doc.to_xml).elements["//ds:KeyInfo"]
    end

    def encoded_certificate(certificate)
      Base64.encode64(certificate.to_der).delete("\n")
    end

    def encoded_digest(document, digest_algorithm)
      digest = digest_algorithm.digest(document)
      Base64.encode64(digest).strip!
    end

    def signature_value(private_key, signature_method, signature_element)
      signature_element = nokogiri_parse(signature_element.to_s)
      noko_signed_info_element = signature_element.at('//ds:Signature/ds:SignedInfo', 'ds' => DSIG)
      canonical_element = noko_signed_info_element.canonicalize(canon_algorithm(C14N))

      signature = private_key.sign(
        algorithm(signature_method).new,
        canonical_element
      )
      Base64.encode64(signature).delete("\n")
    end
  end

  class SignedDocument < BaseDocument

    attr_accessor :signed_element_id
    attr_accessor :errors

    def initialize(response, errors = [])
      super(response)
      @errors = errors
      extract_signed_element_id
    end

    def validate_document(idp_cert_fingerprint, soft = true, options = {})
      # get cert from response
      cert_element = nokogiri_document.at("//ds:X509Certificate", "ds" => DSIG)

      unless cert_element
        if soft
          return false
        else
          raise OneLogin::RubySaml::ValidationError.new("Certificate element missing in response (ds:X509Certificate)")
        end
      end

      base64_cert = cert_element.text
      cert_text = Base64.decode64(base64_cert)
      cert = OpenSSL::X509::Certificate.new(cert_text)

      if options[:fingerprint_alg]
        fingerprint_alg = XMLSecurity::BaseDocument.new.algorithm(options[:fingerprint_alg]).new
      else
        fingerprint_alg = OpenSSL::Digest::SHA1.new
      end
      fingerprint = fingerprint_alg.hexdigest(cert.to_der)

      # check cert matches registered idp cert
      if fingerprint != idp_cert_fingerprint.gsub(/[^a-zA-Z0-9]/,"").downcase
        @errors << "Fingerprint mismatch"
        return soft ? false : (raise OneLogin::RubySaml::ValidationError.new("Fingerprint mismatch"))
      end

      validate_signature(base64_cert, soft)
    end

    def validate_signature(base64_cert, soft = true)
      # check for inclusive namespaces
      inclusive_namespaces = extract_inclusive_namespaces

      # duplicate the node because we remove the signature element below
      document = nokogiri_document.dup

      # create a working copy so we don't modify the original
      working_copy = REXML::Document.new(self.to_s).root

      # store and remove signature node
      sig_element = REXML::XPath.first(
        working_copy,
        "//ds:Signature",
        "ds" => DSIG
      ).remove

      # verify signature
      signed_info_element = REXML::XPath.first(sig_element, "//ds:SignedInfo", "ds"=>DSIG)
      noko_sig_element = document.at('//ds:Signature', 'ds' => DSIG)
      noko_signed_info_element = noko_sig_element.at('./ds:SignedInfo', 'ds' => DSIG)
      canon_algorithm_value = canon_algorithm(algorithm_value(REXML::XPath.first(sig_element, '//ds:CanonicalizationMethod', 'ds' => DSIG)))
      canon_string = noko_signed_info_element.canonicalize(canon_algorithm_value)
      noko_sig_element.remove

      # check digests
      REXML::XPath.each(sig_element, "//ds:Reference", {"ds"=>DSIG}) do |ref|
        uri = ref.attributes.get_attribute("URI").value

        hashed_element = document.at("//*[@ID='#{uri[1..-1]}']")
        canon_algorithm_value = canon_algorithm algorithm_value(REXML::XPath.first(ref, '//ds:CanonicalizationMethod', 'ds' => DSIG))
        canon_hashed_element = hashed_element.canonicalize(canon_algorithm_value, inclusive_namespaces)

        digest_algorithm = algorithm(algorithm_value(REXML::XPath.first(ref, "//ds:DigestMethod", 'ds' => DSIG)))

        hash = digest_algorithm.digest(canon_hashed_element)
        digest_value = Base64.decode64(REXML::XPath.first(ref, "//ds:DigestValue", "ds" => DSIG).text)

        unless digests_match?(hash, digest_value)
          @errors << "Digest mismatch"
          return soft ? false : (raise OneLogin::RubySaml::ValidationError.new("Digest mismatch"))
        end
      end

      base64_signature = REXML::XPath.first(sig_element, "//ds:SignatureValue", "ds" => DSIG).text
      signature = Base64.decode64(base64_signature)

      # get certificate object
      cert_text = Base64.decode64(base64_cert)
      cert = OpenSSL::X509::Certificate.new(cert_text)

      # signature method
      signature_algorithm = algorithm(algorithm_value(REXML::XPath.first(signed_info_element, "//ds:SignatureMethod", "ds" => DSIG)))

      unless cert.public_key.verify(signature_algorithm.new, signature, canon_string)
        @errors << "Key validation error"
        return soft ? false : (raise OneLogin::RubySaml::ValidationError.new("Key validation error"))
      end

      return true
    end

    private

    def digests_match?(hash, digest_value)
      hash == digest_value
    end

    def extract_signed_element_id
      if element = nokogiri_document.at("//ds:Reference", "ds" => DSIG)
        self.signed_element_id = element["URI"].delete("#")
      end
    end

    def extract_inclusive_namespaces
      element = nokogiri_document.at("//ec:InclusiveNamespaces", "ec" => C14N)
      element ? element["PrefixList"].split(" ") : []
    end
  end
end
