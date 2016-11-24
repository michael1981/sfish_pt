# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-20.xml
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
 script_id(14576);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200408-20");
 script_cve_id("CVE-2004-0691", "CVE-2004-0692", "CVE-2004-0693");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200408-20 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200408-20
(Qt: Image loader overflows)


    There are several unspecified bugs in the QImage class which may cause
    crashes or allow execution of arbitrary code as the user running the Qt
    application. These bugs affect the PNG, XPM, BMP, GIF and JPEG image
    types.
  
Impact

    An attacker may exploit these bugs by causing a user to open a
    carefully-constructed image file in any one of these formats. This may
    be accomplished through e-mail attachments (if the user uses KMail), or
    by simply placing a malformed image on a website and then convicing the
    user to load the site in a Qt-based browser (such as Konqueror).
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of Qt.
  
');
script_set_attribute(attribute:'solution', value: '
    All Qt users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=x11-libs/qt-3.3.3"
    # emerge ">=x11-libs/qt-3.3.3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.mandrakesoft.com/security/advisories?name=MDKSA-2004:085');
script_set_attribute(attribute: 'see_also', value: 'http://www.trolltech.com/developer/changes/changes-3.3.3.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0691');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0692');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0693');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200408-20.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200408-20] Qt: Image loader overflows');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Qt: Image loader overflows');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "x11-libs/qt", unaffected: make_list("ge 3.3.3"), vulnerable: make_list("le 3.3.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
