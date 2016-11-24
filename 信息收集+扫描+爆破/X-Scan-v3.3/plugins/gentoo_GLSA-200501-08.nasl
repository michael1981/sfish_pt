# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-08.xml
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
 script_id(16399);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200501-08");
 script_cve_id("CVE-2004-1383", "CVE-2004-1384", "CVE-2004-1385");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200501-08 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200501-08
(phpGroupWare: Various vulnerabilities)


    Several flaws were discovered in phpGroupWare making it vulnerable to
    cross-site scripting attacks, SQL injection, and full path disclosure.
  
Impact

    These vulnerabilities could allow an attacker to perform cross-site
    scripting attacks, execute SQL queries, and disclose the full path of
    the web directory.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All phpGroupWare users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/phpgroupware-0.9.16.004"
    Note: Users with the vhosts USE flag set should manually use
    webapp-config to finalize the update.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.securityfocus.com/archive/1/384492');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1383');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1384');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1385');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200501-08.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200501-08] phpGroupWare: Various vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpGroupWare: Various vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/phpgroupware", unaffected: make_list("ge 0.9.16.004"), vulnerable: make_list("lt 0.9.16.004")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
