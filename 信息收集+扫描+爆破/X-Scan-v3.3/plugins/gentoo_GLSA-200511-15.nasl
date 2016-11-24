# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-15.xml
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
 script_id(20236);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200511-15");
 script_cve_id("CVE-2005-2851");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200511-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200511-15
(Smb4k: Local unauthorized file access)


    A vulnerability leading to unauthorized file access has been
    found. A pre-existing symlink from /tmp/sudoers and /tmp/super.tab to a
    textfile will cause Smb4k to write the contents of these files to the
    target of the symlink, as Smb4k does not check for the existence of
    these files before writing to them.
  
Impact

    An attacker could acquire local privilege escalation by adding
    username(s) to the list of sudoers.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All smb4k users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/smb4k-0.6.4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2851');
script_set_attribute(attribute: 'see_also', value: 'http://smb4k.berlios.de/');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200511-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200511-15] Smb4k: Local unauthorized file access');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Smb4k: Local unauthorized file access');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/smb4k", unaffected: make_list("ge 0.6.4"), vulnerable: make_list("lt 0.6.4")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
