# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200701-25.xml
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
 script_id(24310);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200701-25");
 script_cve_id("CVE-2006-6101", "CVE-2006-6102", "CVE-2006-6103");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200701-25 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200701-25
(X.Org X server: Multiple vulnerabilities)


    Multiple memory corruption vulnerabilities have been found in the
    ProcDbeGetVisualInfo() and the ProcDbeSwapBuffers() of the DBE
    extension, and ProcRenderAddGlyphs() in the Render extension.
  
Impact

    A local attacker could execute arbitrary code with the privileges of
    the user running the X server, typically root.
  
Workaround

    Disable the DBE extension by removing the "Load dbe" directive in the
    Module section of xorg.conf, and explicitly disable the Render
    extension with \' Option "RENDER" "disable" \' in the Extensions section.
    Note: This could affect the functionality of some applications.
  
');
script_set_attribute(attribute:'solution', value: '
    All X.Org X server users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-base/xorg-server-1.1.1-r4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6101');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6102');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6103');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200701-25.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200701-25] X.Org X server: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'X.Org X server: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "x11-base/xorg-server", unaffected: make_list("ge 1.1.1-r4"), vulnerable: make_list("lt 1.1.1-r4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
