# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-26.xml
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
 script_id(15754);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200411-26");
 script_cve_id("CVE-2004-1115", "CVE-2004-1116", "CVE-2004-1117");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200411-26 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200411-26
(GIMPS, SETI@home, ChessBrain: Insecure installation)


    GIMPS, SETI@home and ChessBrain ebuilds install user-owned binaries and
    init scripts which are executed with root privileges.
  
Impact

    This could lead to a local privilege escalation or root compromise.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All GIMPS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sci-misc/gimps-23.9-r1"
    All SETI@home users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sci-misc/setiathome-3.03-r2"
    All ChessBrain users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sci-misc/chessbrain-20407-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1115');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1116');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1117');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200411-26.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200411-26] GIMPS, SETI@home, ChessBrain: Insecure installation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GIMPS, SETI@home, ChessBrain: Insecure installation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sci-misc/gimps", unaffected: make_list("ge 23.9-r1"), vulnerable: make_list("le 23.9")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sci-misc/chessbrain", unaffected: make_list("ge 20407-r1"), vulnerable: make_list("le 20407")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sci-misc/setiathome", unaffected: make_list("ge 3.08-r4", "rge 3.03-r2"), vulnerable: make_list("le 3.08-r3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
