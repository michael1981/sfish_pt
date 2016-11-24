# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200805-11.xml
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
 script_id(32302);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200805-11");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200805-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200805-11
(Chicken: Multiple vulnerabilities)


    Chicken includes a copy of PCRE which is vulnerable to multiple buffer
    overflows and memory corruption vulnerabilities (GLSA 200711-30).
  
Impact

    An attacker could entice a user to process specially crafted regular
    expressions with Chicken, which could possibly lead to the execution of
    arbitrary code, a Denial of Service or the disclosure of sensitive
    information.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Chicken users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-scheme/chicken-3.1.0"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-30.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200805-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200805-11] Chicken: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Chicken: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-scheme/chicken", unaffected: make_list("ge 3.1.0"), vulnerable: make_list("lt 3.1.0")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
