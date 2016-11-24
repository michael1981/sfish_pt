# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200705-09.xml
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
 script_id(25186);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200705-09");
 script_cve_id("CVE-2007-1841");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200705-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200705-09
(IPsec-Tools: Denial of Service)


    The isakmp_info_recv() function in src/racoon/isakmp_inf.c does not
    always check that DELETE (ISAKMP_NPTYPE_D) and NOTIFY (ISAKMP_NPTYPE_N)
    packets are encrypted.
  
Impact

    A remote attacker could send a specially crafted IPsec message to one
    of the two peers during the beginning of phase 1, resulting in the
    termination of the IPsec exchange.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All IPsec-Tools users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-firewall/ipsec-tools-0.6.7"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1841');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200705-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200705-09] IPsec-Tools: Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'IPsec-Tools: Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-firewall/ipsec-tools", unaffected: make_list("ge 0.6.7"), vulnerable: make_list("lt 0.6.7")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
