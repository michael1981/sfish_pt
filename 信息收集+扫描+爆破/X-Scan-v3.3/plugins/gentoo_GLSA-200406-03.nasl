# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-03.xml
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
 script_id(14514);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200406-03");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200406-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200406-03
(sitecopy: Multiple vulnerabilities in included libneon)


    Multiple format string vulnerabilities and a heap overflow vulnerability
    were discovered in the code of the neon library (GLSA 200405-01 and
    200405-13). Current versions of the sitecopy package include their own
    version of this library.
  
Impact

    When connected to a malicious WebDAV server, these vulnerabilities could
    allow execution of arbitrary code with the rights of the user running
    sitecopy.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of sitecopy.
  
');
script_set_attribute(attribute:'solution', value: '
    All sitecopy users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-misc/sitecopy-0.13.4-r2"
    # emerge ">=net-misc/sitecopy-0.13.4-r2"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200405-01.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200405-13.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200406-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200406-03] sitecopy: Multiple vulnerabilities in included libneon');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'sitecopy: Multiple vulnerabilities in included libneon');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/sitecopy", unaffected: make_list("ge 0.13.4-r2"), vulnerable: make_list("le 0.13.4-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
