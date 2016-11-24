# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-13.xml
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
 script_id(14569);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200408-13");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200408-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200408-13
(kdebase, kdelibs: Multiple security issues)


    KDE contains three security issues:
    Insecure handling of temporary files when running KDE applications
    outside of the KDE environment
    DCOPServer creates temporary files in an insecure manner
    The Konqueror browser allows websites to load webpages into a target
    frame of any other open frame-based webpage
  
Impact

    An attacker could exploit these vulnerabilities to create or overwrite
    files with the permissions of another user, compromise the account of users
    running a KDE application and insert arbitrary frames into an otherwise
    trusted webpage.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of kdebase.
  
');
script_set_attribute(attribute:'solution', value: '
    All KDE users should upgrade to the latest versions of kdelibs and kdebase:
    # emerge sync
    # emerge -pv ">=kde-base/kdebase-3.2.3-r1"
    # emerge ">=kde-base/kdebase-3.2.3-r1"
    # emerge -pv ">=kde-base/kdelibs-3.2.3-r1"
    # emerge ">=kde-base/kdelibs-3.2.3-r1"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.kde.org/info/security/advisory-20040811-1.txt');
script_set_attribute(attribute: 'see_also', value: 'http://www.kde.org/info/security/advisory-20040811-2.txt');
script_set_attribute(attribute: 'see_also', value: 'http://www.kde.org/info/security/advisory-20040811-3.txt');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200408-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200408-13] kdebase, kdelibs: Multiple security issues');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'kdebase, kdelibs: Multiple security issues');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "kde-base/kdelibs", unaffected: make_list("ge 3.2.3-r1"), vulnerable: make_list("lt 3.2.3-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "kde-base/kdebase", unaffected: make_list("ge 3.2.3-r1"), vulnerable: make_list("lt 3.2.3-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
