# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200710-11.xml
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
 script_id(27046);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200710-11");
 script_cve_id("CVE-2007-3103", "CVE-2007-4568", "CVE-2007-4990");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200710-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200710-11
(X Font Server: Multiple Vulnerabilities)


    iDefense reported that the xfs init script does not correctly handle a
    race condition when setting permissions of a temporary file
    (CVE-2007-3103). Sean Larsson discovered an integer overflow
    vulnerability in the build_range() function possibly leading to a
    heap-based buffer overflow when handling "QueryXBitmaps" and
    "QueryXExtents" protocol requests (CVE-2007-4568). Sean Larsson also
    discovered an error in the swap_char2b() function possibly leading to a
    heap corruption when handling the same protocol requests
    (CVE-2007-4990).
  
Impact

    The first issue would allow a local attacker to change permissions of
    arbitrary files to be world-writable by performing a symlink attack.
    The second and third issues would allow a local attacker to execute
    arbitrary code with privileges of the user running the X Font Server,
    usually xfs.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All X Font Server users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-apps/xfs-1.0.5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3103');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4568');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4990');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200710-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200710-11] X Font Server: Multiple Vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'X Font Server: Multiple Vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "x11-apps/xfs", unaffected: make_list("ge 1.0.5"), vulnerable: make_list("lt 1.0.5")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
