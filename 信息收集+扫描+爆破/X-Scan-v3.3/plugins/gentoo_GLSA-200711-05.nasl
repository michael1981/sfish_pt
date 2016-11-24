# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200711-05.xml
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
 script_id(27816);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200711-05");
 script_cve_id("CVE-2007-5491", "CVE-2007-5492", "CVE-2007-5692", "CVE-2007-5693", "CVE-2007-5694", "CVE-2007-5695");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200711-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200711-05
(SiteBar: Multiple issues)


    Tim Brown discovered these multiple issues: the translation module does
    not properly sanitize the value to the "dir" parameter (CVE-2007-5491,
    CVE-2007-5694); the translation module also does not sanitize the
    values of the "edit" and "value" parameters which it passes to eval()
    and include() (CVE-2007-5492, CVE-2007-5693); the log-in command does
    not validate the URL to redirect users to after logging in
    (CVE-2007-5695); SiteBar also contains several cross-site scripting
    vulnerabilities (CVE-2007-5692).
  
Impact

    An authenticated attacker in the "Translators" or "Admins" group could
    execute arbitrary code, read arbitrary files and possibly change their
    permissions with the privileges of the user running the web server by
    passing a specially crafted parameter string to the "translator.php"
    file. An unauthenticated attacker could entice a user to browse a
    specially crafted URL, allowing for the execution of script code in the
    context of the user\'s browser, for the theft of browser credentials or
    for a redirection to an arbitrary web site after login.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All SiteBar users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/sitebar-3.3.9"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5491');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5492');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5692');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5693');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5694');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5695');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200711-05] SiteBar: Multiple issues');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'SiteBar: Multiple issues');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/sitebar", unaffected: make_list("ge 3.3.9"), vulnerable: make_list("lt 3.3.9")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
