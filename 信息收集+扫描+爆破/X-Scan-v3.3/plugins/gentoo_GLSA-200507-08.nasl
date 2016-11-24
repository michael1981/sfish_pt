# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-08.xml
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
 script_id(18666);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200507-08");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200507-08 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200507-08
(phpGroupWare, eGroupWare: PHP script injection vulnerability)


    The XML-RPC implementations of phpGroupWare and eGroupWare fail to
    sanitize input sent to the XML-RPC server using the "POST" method.
  
Impact

    A remote attacker could exploit the XML-RPC vulnerability to
    execute arbitrary PHP script code by sending specially crafted XML data
    to the XML-RPC servers of phpGroupWare or eGroupWare.
  
Workaround

    There are no known workarounds at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All phpGroupWare users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-app/phpgroupware-0.9.16.006"
    All eGroupWare users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-app/egroupware-1.0.0.008"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1921');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200507-08.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200507-08] phpGroupWare, eGroupWare: PHP script injection vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpGroupWare, eGroupWare: PHP script injection vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/phpgroupware", unaffected: make_list("ge 0.9.16.006"), vulnerable: make_list("lt 0.9.16.006")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-apps/egroupware", unaffected: make_list("ge 1.0.0.008"), vulnerable: make_list("lt 1.0.0.008")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
