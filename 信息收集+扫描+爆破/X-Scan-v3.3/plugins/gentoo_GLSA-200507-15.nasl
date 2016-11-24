# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-15.xml
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
 script_id(19211);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200507-15");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200507-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200507-15
(PHP: Script injection through XML-RPC)


    James Bercegay has discovered that the XML-RPC implementation in
    PHP fails to sanitize input passed in an XML document, which is used in
    an "eval()" statement.
  
Impact

    A remote attacker could exploit the XML-RPC vulnerability to
    execute arbitrary PHP script code by sending specially crafted XML data
    to applications making use of this XML-RPC implementation.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All PHP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-php/php-4.4.0"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1921');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200507-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200507-15] PHP: Script injection through XML-RPC');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PHP: Script injection through XML-RPC');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-php/php", unaffected: make_list("ge 4.4.0"), vulnerable: make_list("lt 4.4.0")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
