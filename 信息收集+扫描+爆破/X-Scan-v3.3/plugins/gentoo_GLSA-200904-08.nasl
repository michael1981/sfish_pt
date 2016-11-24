# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200904-08.xml
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
 script_id(36096);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200904-08");
 script_cve_id("CVE-2009-0590");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200904-08 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200904-08
(OpenSSL: Denial of Service)


    The ASN1_STRING_print_ex() function does not properly check the
    provided length of a BMPString or UniversalString, leading to an
    invalid memory access.
  
Impact

    A remote attacker could entice a user or automated system to print a
    specially crafted certificate, possibly leading to a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All OpenSSL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-libs/openssl-0.9.8k"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0590');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200904-08.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200904-08] OpenSSL: Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenSSL: Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-libs/openssl", unaffected: make_list("ge 0.9.8k"), vulnerable: make_list("lt 0.9.8k")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
