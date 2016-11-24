# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200902-02.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(35673);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200902-02");
 script_cve_id("CVE-2008-5077");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200902-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200902-02
(OpenSSL: Certificate validation error)


    The Google Security Team reported that several functions incorrectly
    check the result after calling the EVP_VerifyFinal() function, allowing
    a malformed signature to be treated as a good signature rather than as
    an error. This issue affects the signature checks on DSA and ECDSA keys
    used with SSL/TLS.
  
Impact

    A remote attacker could exploit this vulnerability and spoof arbitrary
    names to conduct Man-In-The-Middle attacks and intercept sensitive
    information.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All OpenSSL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-libs/openssl-0.9.8j"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5077');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200902-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200902-02] OpenSSL: Certificate validation error');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenSSL: Certificate validation error');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-libs/openssl", unaffected: make_list("ge 0.9.8j"), vulnerable: make_list("lt 0.9.8j")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
