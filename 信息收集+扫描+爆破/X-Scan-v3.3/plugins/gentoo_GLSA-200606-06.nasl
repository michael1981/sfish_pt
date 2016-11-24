# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-06.xml
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
 script_id(21667);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200606-06");
 script_cve_id("CVE-2006-1945", "CVE-2006-2237");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200606-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200606-06
(AWStats: Remote execution of arbitrary code)


    Hendrik Weimer has found that if updating the statistics via the
    web frontend is enabled, it is possible to inject arbitrary code via a
    pipe character in the "migrate" parameter. Additionally, r0t has
    discovered that AWStats fails to properly sanitize user-supplied input
    in awstats.pl.
  
Impact

    A remote attacker can execute arbitrary code on the server in the
    context of the application running the AWStats CGI script if updating
    of the statistics via web frontend is allowed. Nonetheless, all
    configurations are affected by a cross-site scripting vulnerability in
    awstats.pl, allowing a remote attacker to execute arbitrary scripts
    running in the context of the victim\'s browser.
  
Workaround

    Disable statistics updates using the web frontend to avoid code
    injection. However, there is no known workaround at this time
    concerning the cross-site scripting vulnerability.
  
');
script_set_attribute(attribute:'solution', value: '
    All AWStats users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-misc/awstats-6.5-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1945');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2237');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200606-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200606-06] AWStats: Remote execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'AWStats: Remote execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-misc/awstats", unaffected: make_list("ge 6.5-r1"), vulnerable: make_list("lt 6.5-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
