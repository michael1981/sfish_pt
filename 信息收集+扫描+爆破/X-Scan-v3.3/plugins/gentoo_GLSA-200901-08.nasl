# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200901-08.xml
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
 script_id(35356);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200901-08");
 script_cve_id("CVE-2004-2155", "CVE-2006-6358", "CVE-2006-6359");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200901-08 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200901-08
(Online-Bookmarks: Multiple vulnerabilities)


    The following vulnerabilities were reported:
    Authentication bypass when directly requesting certain pages
    (CVE-2004-2155).
    Insufficient input validation in the login
    function in auth.inc (CVE-2006-6358).
    Unspecified cross-site
    scripting vulnerability (CVE-2006-6359).
  
Impact

    A remote attacker could exploit these vulnerabilities to bypass
    authentication mechanisms, execute arbitrary SQL statements or inject
    arbitrary web scripts.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Online-Bookmarks users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/online-bookmarks-0.6.28"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2155');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6358');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6359');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200901-08.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200901-08] Online-Bookmarks: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Online-Bookmarks: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/online-bookmarks", unaffected: make_list("ge 0.6.28"), vulnerable: make_list("lt 0.6.28")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
