# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-16.xml
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
 script_id(16003);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200412-16");
 script_cve_id("CVE-2004-1171", "CVE-2004-1158");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200412-16 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200412-16
(kdelibs, kdebase: Multiple vulnerabilities)


    Daniel Fabian discovered that the KDE core libraries contain a
    flaw allowing password disclosure by making a link to a remote file.
    When creating this link, the resulting URL contains authentication
    credentials used to access the remote file (CAN 2004-1171).
    The Konqueror webbrowser allows websites to load webpages into a window
    or tab currently used by another website (CAN-2004-1158).
  
Impact

    A malicious user could have access to the authentication
    credentials of other users depending on the file permissions.
    A malicious website could use the window injection vulnerability to
    load content in a window apparently belonging to another website.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All kdelibs users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=kde-base/kdelibs-3.2.3-r4"
    All kdebase users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=kde-base/kdebase-3.2.3-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.kde.org/info/security/advisory-20041209-1.txt');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1171');
script_set_attribute(attribute: 'see_also', value: 'http://www.kde.org/info/security/advisory-20041213-1.txt');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1158');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200412-16.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200412-16] kdelibs, kdebase: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'kdelibs, kdebase: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "kde-base/kdebase", unaffected: make_list("rge 3.2.3-r3", "rge 3.3.1-r2"), vulnerable: make_list("lt 3.3.2-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "kde-base/kdelibs", unaffected: make_list("rge 3.2.3-r4", "rge 3.3.1-r2", "ge 3.3.2-r1"), vulnerable: make_list("lt 3.3.2-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
