# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-22.xml
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
 script_id(14767);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200409-22");
 script_cve_id("CVE-2004-0875");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200409-22 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200409-22
(phpGroupWare: XSS vulnerability in wiki module)


    Due to an input validation error, the wiki module in the phpGroupWare
    suite is vulnerable to cross site scripting attacks.
  
Impact

    This vulnerability gives an attacker the ability to inject and execute
    malicious script code, potentially compromising the victim\'s browser.
  
Workaround

    The is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All phpGroupWare users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=www-apps/phpgroupware-0.9.16.003"
    # emerge ">=www-apps/phpgroupware-0.9.16.003"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://downloads.phpgroupware.org/changelog');
script_set_attribute(attribute: 'see_also', value: 'http://secunia.com/advisories/12466/');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0875');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200409-22.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200409-22] phpGroupWare: XSS vulnerability in wiki module');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpGroupWare: XSS vulnerability in wiki module');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/phpgroupware", unaffected: make_list("ge 0.9.16.003"), vulnerable: make_list("lt 0.9.16.003")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
