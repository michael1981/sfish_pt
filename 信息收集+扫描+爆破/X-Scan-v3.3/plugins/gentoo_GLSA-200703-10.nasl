# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200703-10.xml
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
 script_id(24802);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200703-10");
 script_cve_id("CVE-2007-0537", "CVE-2007-0478");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200703-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200703-10
(KHTML: Cross-site scripting (XSS) vulnerability)


    The KHTML code allows for the execution of JavaScript code located
    inside the "Title" HTML element, a related issue to the Safari error
    found by Jose Avila.
  
Impact

    When viewing a HTML page that renders unsanitized attacker-supplied
    input in the page title, Konqueror and other parts of KDE will execute
    arbitrary JavaScript code contained in the page title, allowing for the
    theft of browser session data or cookies.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All KDElibs users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=kde-base/kdelibs-3.5.5-r8"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0537');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0478');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200703-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200703-10] KHTML: Cross-site scripting (XSS) vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'KHTML: Cross-site scripting (XSS) vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "kde-base/kdelibs", unaffected: make_list("ge 3.5.5-r8"), vulnerable: make_list("lt 3.5.5-r8")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
