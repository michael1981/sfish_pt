# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-02.xml
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
 script_id(14467);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200404-02");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200404-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200404-02
(KDE Personal Information Management Suite Remote Buffer Overflow Vulnerability)


    A buffer overflow may occur in KDE-PIM\'s VCF file reader when a maliciously
    crafted VCF file is opened by a user on a vulnerable system.
  
Impact

    A remote attacker may unauthorized access to a user\'s personal data or
    execute commands with the user\'s privileges.
  
Workaround

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version of the affected package.
  
');
script_set_attribute(attribute:'solution', value: '
    KDE users should upgrade to version 3.1.5 or later:
    # emerge sync
    # emerge -pv ">=kde-base/kde-3.1.5"
    # emerge ">=kde-base/kde-3.1.5"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2003-0988');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200404-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200404-02] KDE Personal Information Management Suite Remote Buffer Overflow Vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'KDE Personal Information Management Suite Remote Buffer Overflow Vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "kde-base/kde", unaffected: make_list("ge 3.1.5"), vulnerable: make_list("le 3.1.4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
