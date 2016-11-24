# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200812-07.xml
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
 script_id(35024);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200812-07");
 script_cve_id("CVE-2008-3102", "CVE-2008-4687", "CVE-2008-4688", "CVE-2008-4689");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200812-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200812-07
(Mantis: Multiple vulnerabilities)


    Multiple issues have been reported in Mantis:
    EgiX reported that manage_proj_page.php does not correctly sanitize the
    sort parameter before passing it to create_function() in
    core/utility_api.php (CVE-2008-4687).
    Privileges of viewers are not sufficiently checked before composing a
    link with issue data in the source anchor (CVE-2008-4688).
    Mantis does not unset the session cookie during logout (CVE-2008-4689).
    Mantis does not set the secure flag for the session cookie in an HTTPS
    session (CVE-2008-3102).
  
Impact

    Remote unauthenticated attackers could exploit these vulnerabilities to
    execute arbitrary PHP commands, disclose sensitive issue data, or
    hijack a user\'s sessions.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Mantis users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/mantisbt-1.1.4-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3102');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4687');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4688');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4689');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200812-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200812-07] Mantis: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mantis: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/mantisbt", unaffected: make_list("ge 1.1.4-r1"), vulnerable: make_list("lt 1.1.4-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
