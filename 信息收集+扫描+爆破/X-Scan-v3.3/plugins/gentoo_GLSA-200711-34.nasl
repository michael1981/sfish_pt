# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200711-34.xml
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
 script_id(28323);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200711-34");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200711-34 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200711-34
(CSTeX: Multiple vulnerabilities)


    Multiple issues were found in the teTeX 2 codebase that CSTeX builds
    upon (GLSA 200709-17, GLSA 200711-26). CSTeX also includes vulnerable
    code from the GD library (GLSA 200708-05), from Xpdf (GLSA 200709-12,
    GLSA 200711-22) and from T1Lib (GLSA 200710-12).
  
Impact

    Remote attackers could possibly execute arbitrary code and local
    attackers could possibly overwrite arbitrary files with the privileges
    of the user running CSTeX via multiple vectors.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    CSTeX is not maintained upstream, so the package was masked in Portage.
    We recommend that users unmerge CSTeX:
    # emerge --unmerge app-text/cstetex
    As an alternative, users should upgrade their systems to use teTeX or
    TeX Live with its Babel packages.
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200708-05.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200709-12.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200709-17.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200710-12.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-22.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-26.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-34.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200711-34] CSTeX: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'CSTeX: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/cstetex", unaffected: make_list(), vulnerable: make_list("lt 2.0.2-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
