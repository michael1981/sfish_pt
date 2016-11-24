# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-12.xml
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
 script_id(18045);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200504-12");
 script_cve_id("CVE-2005-1064");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200504-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200504-12
(rsnapshot: Local privilege escalation)


    The copy_symlink() subroutine in rsnapshot follows symlinks when
    changing file ownership, instead of changing the ownership of the
    symlink itself.
  
Impact

    Under certain circumstances, local attackers can exploit this
    vulnerability to take ownership of arbitrary files, resulting in local
    privilege escalation.
  
Workaround

    The copy_symlink() subroutine is not called if the cmd_cp parameter has
    been enabled.
  
');
script_set_attribute(attribute:'solution', value: '
    All rsnapshot users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose app-backup/rsnapshot
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.rsnapshot.org/security/2005/001.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1064');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200504-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200504-12] rsnapshot: Local privilege escalation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'rsnapshot: Local privilege escalation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-backup/rsnapshot", unaffected: make_list("ge 1.2.1", "rge 1.1.7"), vulnerable: make_list("lt 1.2.1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
