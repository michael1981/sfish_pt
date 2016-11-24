# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-01.xml
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
 script_id(18605);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200507-01");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200507-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200507-01
(PEAR XML-RPC, phpxmlrpc: PHP script injection vulnerability)


    James Bercegay of GulfTech Security Research discovered that the
    PEAR XML-RPC and phpxmlrpc libraries fail to sanatize input sent using
    the "POST" method.
  
Impact

    A remote attacker could exploit this vulnerability to execute
    arbitrary PHP script code by sending a specially crafted XML document
    to web applications making use of these libraries.
  
Workaround

    There are no known workarounds at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All PEAR-XML_RPC users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-php/PEAR-XML_RPC-1.3.1"
    All phpxmlrpc users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-php/phpxmlrpc-1.1.1"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1921');
script_set_attribute(attribute: 'see_also', value: 'http://www.gulftech.org/?node=research&article_id=00088-07022005');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200507-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200507-01] PEAR XML-RPC, phpxmlrpc: PHP script injection vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PEAR XML-RPC, phpxmlrpc: PHP script injection vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-php/PEAR-XML_RPC", unaffected: make_list("ge 1.3.1"), vulnerable: make_list("lt 1.3.1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "dev-php/phpxmlrpc", unaffected: make_list("ge 1.1.1"), vulnerable: make_list("lt 1.1.1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
