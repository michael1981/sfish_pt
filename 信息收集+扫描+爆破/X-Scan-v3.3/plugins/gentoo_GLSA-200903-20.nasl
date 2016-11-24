# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200903-20.xml
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
 script_id(35818);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200903-20");
 script_cve_id("CVE-2008-5918", "CVE-2008-5919", "CVE-2009-0240");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200903-20 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200903-20
(WebSVN: Multiple vulnerabilities)


    James Bercegay of GulfTech Security reported a Cross-site scripting
    (XSS) vulnerability in the getParameterisedSelfUrl() function in
    index.php (CVE-2008-5918) and a directory traversal vulnerability in
    rss.php when magic_quotes_gpc is disabled (CVE-2008-5919).
    Bas van Schaik reported that listing.php does not properly enforce
    access restrictions when using an SVN authz file to authenticate users
    (CVE-2009-0240).
  
Impact

    A remote attacker can exploit these vulnerabilities to overwrite
    arbitrary files, to read changelogs or diffs for restricted projects
    and to hijack a user\'s session.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All WebSVN users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/websvn-2.1.0"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5918');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5919');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0240');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200903-20.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200903-20] WebSVN: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'WebSVN: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/websvn", unaffected: make_list("ge 2.1.0"), vulnerable: make_list("lt 2.1.0")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
