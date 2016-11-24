# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200805-07.xml
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
 script_id(32209);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200805-07");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200805-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200805-07
(Linux Terminal Server Project: Multiple vulnerabilities)


    LTSP version 4.2, ships prebuilt copies of programs such as the Linux
    Kernel, the X.org X11 server (GLSA 200705-06, GLSA 200710-16, GLSA
    200801-09), libpng (GLSA 200705-24, GLSA 200711-08), Freetype (GLSA
    200705-02, GLSA 200705-22) and OpenSSL (GLSA 200710-06, GLSA 200710-30)
    which were subject to multiple security vulnerabilities since 2006.
    Please note that the given list of vulnerabilities might not be
    exhaustive.
  
Impact

    A remote attacker could possibly exploit vulnerabilities in the
    aforementioned programs and execute arbitrary code, disclose sensitive
    data or cause a Denial of Service within LTSP 4.2 clients.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    LTSP 4.2 is not maintained upstream in favor of version 5. Since
    version 5 is not yet available in Gentoo, the package has been masked.
    We recommend that users unmerge LTSP:
    # emerge --unmerge net-misc/ltsp
    If you have a requirement for Linux Terminal Servers, please either set
    up a terminal server by hand or use one of the distributions that
    already migrated to LTSP 5. If you want to contribute to the
    integration of LTSP 5 in Gentoo, or want to follow its development,
    find details in bug 177580.
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200705-02.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200705-06.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200705-22.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200705-24.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200710-06.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200710-16.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200710-30.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-08.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200801-09.xml');
script_set_attribute(attribute: 'see_also', value: 'https://bugs.gentoo.org/177580');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200805-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200805-07] Linux Terminal Server Project: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Linux Terminal Server Project: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/ltsp", unaffected: make_list(), vulnerable: make_list("lt 5.0")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
