# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200508-20.xml
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
 script_id(19573);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200508-20");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200508-20 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200508-20
(phpGroupWare: Multiple vulnerabilities)


    phpGroupWare improperly validates the "mid" parameter retrieved
    via a forum post. The current version of phpGroupWare also adds several
    safeguards to prevent XSS issues, and disables the use of a potentially
    vulnerable XML-RPC library.
  
Impact

    A remote attacker may leverage the XML-RPC vulnerability to
    execute arbitrary PHP script code. He could also create a specially
    crafted request that will reveal private posts.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All phpGroupWare users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/phpgroupware-0.9.16.008"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2005-2498');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2005-2600');
script_set_attribute(attribute: 'see_also', value: 'http://secunia.com/advisories/16414');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200508-20.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200508-20] phpGroupWare: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpGroupWare: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/phpgroupware", unaffected: make_list("ge 0.9.16.008"), vulnerable: make_list("lt 0.9.16.008")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
