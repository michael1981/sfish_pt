# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200710-06.xml
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
 script_id(26946);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200710-06");
 script_cve_id("CVE-2006-3738", "CVE-2007-3108", "CVE-2007-5135");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200710-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200710-06
(OpenSSL: Multiple vulnerabilities)


    Moritz Jodeit reported an off-by-one error in the
    SSL_get_shared_ciphers() function, resulting from an incomplete fix of
    CVE-2006-3738. A flaw has also been reported in the
    BN_from_montgomery() function in crypto/bn/bn_mont.c when performing
    Montgomery multiplication.
  
Impact

    A remote attacker sending a specially crafted packet to an application
    relying on OpenSSL could possibly execute arbitrary code with the
    privileges of the user running the application. A local attacker could
    perform a side channel attack to retrieve the RSA private keys.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All OpenSSL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-libs/openssl-0.9.8e-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3738');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3108');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5135');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200710-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200710-06] OpenSSL: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenSSL: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-libs/openssl", unaffected: make_list("ge 0.9.8e-r3"), vulnerable: make_list("lt 0.9.8e-r3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
