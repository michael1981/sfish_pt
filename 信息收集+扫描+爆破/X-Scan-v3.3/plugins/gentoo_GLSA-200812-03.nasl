# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200812-03.xml
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
 script_id(35020);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200812-03");
 script_cve_id("CVE-2008-3651", "CVE-2008-3652");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200812-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200812-03
(IPsec-Tools: racoon Denial of Service)


    Two Denial of Service vulnerabilities have been reported in racoon:
    The vendor reported a memory leak in racoon/proposal.c that can be
    triggered via invalid proposals (CVE-2008-3651).
    Krzysztof Piotr Oledzk reported that src/racoon/handler.c does not
    remove an "orphaned ph1" (phase 1) handle when it has been initiated
    remotely (CVE-2008-3652).
  
Impact

    An attacker could exploit these vulnerabilities to cause a Denial of
    Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All IPsec-Tools users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-firewall/ipsec-tools-0.7.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3651');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3652');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200812-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200812-03] IPsec-Tools: racoon Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'IPsec-Tools: racoon Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-firewall/ipsec-tools", unaffected: make_list("ge 0.7.1"), vulnerable: make_list("lt 0.7.1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
