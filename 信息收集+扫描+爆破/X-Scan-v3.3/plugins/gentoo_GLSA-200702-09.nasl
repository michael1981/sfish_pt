# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200702-09.xml
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
 script_id(24721);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200702-09");
 script_cve_id("CVE-2006-6609", "CVE-2006-6610");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200702-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200702-09
(Nexuiz: Multiple vulnerabilities)


    Nexuiz fails to correctly validate input within "clientcommands". There
    is also a failure to correctly handle connection attempts from remote
    hosts.
  
Impact

    Using a specially crafted "clientcommand" a remote attacker can cause a
    buffer overflow in Nexuiz which could result in the execution of
    arbitrary code. Additionally, there is a Denial of Service
    vulnerability in Nexuiz allowing an attacker to cause Nexuiz to crash
    or to run out of resources by overloading it with specially crafted
    connection requests.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Nexuiz users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=games-fps/nexuiz-2.2.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6609');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6610');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200702-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200702-09] Nexuiz: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Nexuiz: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "games-fps/nexuiz", unaffected: make_list("ge 2.2.1"), vulnerable: make_list("lt 2.2.1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
