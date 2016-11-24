# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200611-13.xml
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
 script_id(23707);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200611-13");
 script_cve_id("CVE-2006-5461");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200611-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200611-13
( message vulnerability)


    Avahi does not check that the netlink messages come from the kernel
    instead of a user-space process.
  
Impact

    A local attacker could exploit this vulnerability by crafting malicious
    netlink messages and trick Avahi to react to fake network changes. This
    could lead users to connect to untrusted services without knowing.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Avahi users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-dns/avahi-0.6.15"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5461');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200611-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200611-13]  message vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: ' message vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-dns/avahi", unaffected: make_list("ge 0.6.15"), vulnerable: make_list("lt 0.6.15")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
