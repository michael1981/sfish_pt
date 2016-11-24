# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-07.xml
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
 script_id(18656);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200507-07");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200507-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200507-07
(phpWebSite: Multiple vulnerabilities)


    phpWebSite fails to sanitize input sent to the XML-RPC server
    using the "POST" method. Other unspecified vulnerabilities have been
    discovered by Diabolic Crab of Hackers Center.
  
Impact

    A remote attacker could exploit the XML-RPC vulnerability to
    execute arbitrary PHP script code by sending specially crafted XML data
    to phpWebSite. The undisclosed vulnerabilities do have an unknown
    impact.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All phpWebSite users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-app/phpwebsite-0.10.1-r1"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1921');
script_set_attribute(attribute: 'see_also', value: 'http://phpwebsite.appstate.edu/index.php?module=announce&ANN_user_op=view&ANN_id=989');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200507-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200507-07] phpWebSite: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpWebSite: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/phpwebsite", unaffected: make_list("ge 0.10.1-r1"), vulnerable: make_list("lt 0.10.1-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
