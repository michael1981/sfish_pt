# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-05.xml
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
 script_id(14561);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200408-05");
 script_cve_id("CVE-2004-2570");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200408-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200408-05
(Opera: Multiple new vulnerabilities)


    Multiple vulnerabilities have been found in the Opera web browser.
    Opera fails to deny write access to the "location" browser object. An
    attacker can overwrite methods in this object and gain script access to
    any page that uses one of these methods. Furthermore, access to file://
    URLs is possible even from pages loaded using other protocols. Finally,
    spoofing a legitimate web page is still possible, despite the fixes
    announced in GLSA 200407-15.
  
Impact

    By enticing an user to visit specially crafted web pages, an attacker
    can read files located on the victim\'s file system, read emails written
    or received by M2, Opera\'s mail program, steal cookies, spoof URLs,
    track user browsing history, etc.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version.
  
');
script_set_attribute(attribute:'solution', value: '
    All Opera users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=www-client/opera-7.54"
    # emerge ">=www-client/opera-7.54"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://www.opera.com/linux/changelogs/754/');
script_set_attribute(attribute: 'see_also', value: 'http://archives.neohapsis.com/archives/fulldisclosure/2004-07/1056.html');
script_set_attribute(attribute: 'see_also', value: 'http://www.greymagic.com/security/advisories/gm008-op/');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2570');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200408-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200408-05] Opera: Multiple new vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Opera: Multiple new vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-client/opera", unaffected: make_list("ge 7.54"), vulnerable: make_list("le 7.53")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
