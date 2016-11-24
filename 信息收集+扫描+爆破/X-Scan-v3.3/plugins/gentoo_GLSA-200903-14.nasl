# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200903-14.xml
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
 script_id(35812);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200903-14");
 script_cve_id("CVE-2009-0025", "CVE-2009-0265");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200903-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200903-14
(BIND: Incorrect signature verification)


    BIND does not properly check the return value from the OpenSSL
    functions to verify DSA (CVE-2009-0025) and RSA (CVE-2009-0265)
    certificates.
  
Impact

    A remote attacker could bypass validation of the certificate chain to
    spoof DNSSEC-authenticated records.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All BIND users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-dns/bind-9.4.3_p1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0025');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0265');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200903-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200903-14] BIND: Incorrect signature verification');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'BIND: Incorrect signature verification');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-dns/bind", unaffected: make_list("ge 9.4.3_p1"), vulnerable: make_list("lt 9.4.3_p1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
