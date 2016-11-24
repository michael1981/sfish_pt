# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200705-10.xml
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
 script_id(25187);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200705-10");
 script_cve_id("CVE-2007-1003", "CVE-2007-1351", "CVE-2007-1352");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200705-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200705-10
(LibXfont, TightVNC: Multiple vulnerabilities)


    The libXfont code is prone to several integer overflows, in functions
    ProcXCMiscGetXIDList(), bdfReadCharacters() and FontFileInitTable().
    TightVNC contains a local copy of this code and is also affected.
  
Impact

    A local attacker could use a specially crafted BDF Font to gain root
    privileges on the vulnerable host.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All libXfont users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-libs/libXfont-1.2.7-r1"
    All TightVNC users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/tightvnc-1.2.9-r4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1003');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1351');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1352');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200705-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200705-10] LibXfont, TightVNC: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'LibXfont, TightVNC: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/tightvnc", unaffected: make_list("ge 1.2.9-r4"), vulnerable: make_list("lt 1.2.9-r4")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "x11-libs/libXfont", unaffected: make_list("ge 1.2.7-r1"), vulnerable: make_list("lt 1.2.7-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
