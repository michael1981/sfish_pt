# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200710-30.xml
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
 script_id(27592);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200710-30");
 script_cve_id("CVE-2007-4995");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200710-30 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200710-30
(OpenSSL: Remote execution of arbitrary code)


    Andy Polyakov reported a vulnerability in the OpenSSL toolkit, that is
    caused due to an unspecified off-by-one error within the DTLS
    implementation.
  
Impact

    A remote attacker could exploit this issue to execute arbitrary code or
    cause a Denial of Service. Only clients and servers explicitly using
    DTLS are affected, systems using SSL and TLS are not.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All OpenSSL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-libs/openssl-0.9.8f"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4995');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200710-30.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200710-30] OpenSSL: Remote execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenSSL: Remote execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-libs/openssl", unaffected: make_list("ge 0.9.8f"), vulnerable: make_list("lt 0.9.8f")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
