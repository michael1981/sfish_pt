# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200801-18.xml
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
 script_id(30135);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200801-18");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200801-18 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200801-18
(Kazehakase: Multiple vulnerabilities)


    Kazehakase includes a copy of PCRE which is vulnerable to multiple
    buffer overflows and memory corruptions vulnerabilities (GLSA
    200711-30).
  
Impact

    A remote attacker could entice a user to open specially crafted input
    (e.g bookmarks) with Kazehakase, which could possibly lead to the
    execution of arbitrary code, a Denial of Service or the disclosure of
    sensitive information.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Kazehakase users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/kazehakase-0.5.0"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-30.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200801-18.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200801-18] Kazehakase: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Kazehakase: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-client/kazehakase", unaffected: make_list("ge 0.5.0"), vulnerable: make_list("lt 0.5.0")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
