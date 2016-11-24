# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200512-15.xml
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
 script_id(20356);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200512-15");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200512-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200512-15
(rssh: Privilege escalation)


    Max Vozeler discovered that the rssh_chroot_helper command allows
    local users to chroot into arbitrary directories.
  
Impact

    A local attacker could exploit this vulnerability to gain root
    privileges by chrooting into arbitrary directories.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All rssh users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-shells/rssh-2.3.0"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3345');
script_set_attribute(attribute: 'see_also', value: 'http://www.pizzashack.org/rssh/security.shtml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200512-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200512-15] rssh: Privilege escalation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'rssh: Privilege escalation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-shells/rssh", unaffected: make_list("ge 2.3.0"), vulnerable: make_list("lt 2.3.0")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
