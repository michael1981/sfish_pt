# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200805-13.xml
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
 script_id(32304);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200805-13");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200805-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200805-13
(PTeX: Multiple vulnerabilities)


    Multiple issues were found in the teTeX 2 codebase that PTeX builds
    upon (GLSA 200709-17, GLSA 200711-26). PTeX also includes vulnerable
    code from the GD library (GLSA 200708-05), from Xpdf (GLSA 200709-12,
    GLSA 200711-22) and from T1Lib (GLSA 200710-12).
  
Impact

    Remote attackers could possibly execute arbitrary code and local
    attackers could possibly overwrite arbitrary files with the privileges
    of the user running PTeX via multiple vectors, e.g. enticing users to
    open specially crafted files.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All PTeX users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/ptex-3.1.10_p20071203"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200708-05.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200709-12.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200709-17.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200710-12.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-22.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-26.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200805-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200805-13] PTeX: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PTeX: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/ptex", unaffected: make_list("ge 3.1.10_p20071203"), vulnerable: make_list("lt 3.1.10_p20071203")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
