# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200701-17.xml
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
 script_id(24253);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200701-17");
 script_cve_id("CVE-2007-0235");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200701-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200701-17
(libgtop: Privilege escalation)


    Liu Qishuai discovered that glibtop_get_proc_map_s() in
    sysdeps/linux/procmap.c does not properly allocate memory for storing a
    filename, allowing certain filenames to cause the buffer to overflow on
    the stack.
  
Impact

    By tricking a victim into executing an application that uses the
    libgtop library (e.g. libgtop_daemon or gnome-system-monitor), a local
    attacker could specify a specially crafted filename to be used by
    libgtop causing a buffer overflow and possibly execute arbitrary code
    with the rights of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All libgtop users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=gnome-base/libgtop-2.14.6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0235');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200701-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200701-17] libgtop: Privilege escalation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libgtop: Privilege escalation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "gnome-base/libgtop", unaffected: make_list("ge 2.14.6"), vulnerable: make_list("lt 2.14.6")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
