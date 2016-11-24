# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200510-20.xml
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
 script_id(20102);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200510-20");
 script_cve_id("CVE-2005-3323");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200510-20 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200510-20
(Zope: File inclusion through RestructuredText)


    Zope honors file inclusion directives in RestructuredText objects by
    default.
  
Impact

    An attacker could exploit the vulnerability by sending malicious input
    that would be interpreted in a RestructuredText Zope object,
    potentially resulting in the execution of arbitrary Zope code with the
    rights of the Zope server.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Zope users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose net-zope/zope
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.zope.org/Products/Zope/Hotfix_2005-10-09/security_alert');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3323');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200510-20.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200510-20] Zope: File inclusion through RestructuredText');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Zope: File inclusion through RestructuredText');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-zope/zope", unaffected: make_list("ge 2.7.8"), vulnerable: make_list("lt 2.7.8", "eq 2.8.0", "eq 2.8.1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
