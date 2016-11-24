# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200510-11.xml
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
 script_id(20031);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200510-11");
 script_cve_id("CVE-2005-2969");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200510-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200510-11
(OpenSSL: SSL 2.0 protocol rollback)


    Applications setting the SSL_OP_MSIE_SSLV2_RSA_PADDING option (or the
    SSL_OP_ALL option, that implies it) can be forced by a third-party to
    fallback to the less secure SSL 2.0 protocol, even if both parties
    support the more secure SSL 3.0 or TLS 1.0 protocols.
  
Impact

    A man-in-the-middle attacker can weaken the encryption used to
    communicate between two parties, potentially revealing sensitive
    information.
  
Workaround

    If possible, disable the use of SSL 2.0 in all OpenSSL-enabled
    applications.
  
');
script_set_attribute(attribute:'solution', value: '
    All OpenSSL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-libs/openssl
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2969');
script_set_attribute(attribute: 'see_also', value: 'http://www.openssl.org/news/secadv_20051011.txt ');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200510-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200510-11] OpenSSL: SSL 2.0 protocol rollback');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenSSL: SSL 2.0 protocol rollback');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-libs/openssl", unaffected: make_list("ge 0.9.7h", "rge 0.9.7g-r1", "rge 0.9.7e-r2"), vulnerable: make_list("lt 0.9.7h")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
