# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-19.xml
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
 script_id(14552);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200407-19");
 script_cve_id("CVE-2004-1437");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200407-19 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200407-19
(Pavuk: Digest authentication helper buffer overflow)


    Pavuk contains several buffer overflow vulnerabilities in the code
    handling digest authentication.
  
Impact

    An attacker could cause a buffer overflow, leading to arbitrary code
    execution with the rights of the user running Pavuk.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of Pavuk.
  
');
script_set_attribute(attribute:'solution', value: '
    All Pavuk users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-misc/pavuk-0.9.28-r3"
    # emerge ">=net-misc/pavuk-0.9.28-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1437');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200407-19.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200407-19] Pavuk: Digest authentication helper buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Pavuk: Digest authentication helper buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/pavuk", unaffected: make_list("ge 0.9.28-r3"), vulnerable: make_list("le 0.9.28-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
