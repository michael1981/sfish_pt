# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-19.xml
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
 script_id(15694);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200411-19");
 script_cve_id("CVE-2004-0456");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200411-19 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200411-19
(Pavuk: Multiple buffer overflows)


    Pavuk contains several buffer overflow vulnerabilities in the code handling digest authentication and HTTP header processing. This issue is similar to GLSA 200407-19, but contains more vulnerabilities.
  
Impact

    A remote attacker could cause a buffer overflow, leading to arbitrary code execution with the rights of the user running Pavuk.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Pavuk users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/pavuk-0.9.31"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200407-19.xml');
script_set_attribute(attribute: 'see_also', value: 'http://secunia.com/advisories/13120/');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0456');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200411-19.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200411-19] Pavuk: Multiple buffer overflows');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Pavuk: Multiple buffer overflows');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/pavuk", unaffected: make_list("ge 0.9.31"), vulnerable: make_list("lt 0.9.31")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
