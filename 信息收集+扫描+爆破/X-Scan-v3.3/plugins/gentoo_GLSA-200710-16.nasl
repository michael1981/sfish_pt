# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200710-16.xml
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
 script_id(27051);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200710-16");
 script_cve_id("CVE-2007-4730");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200710-16 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200710-16
(X.Org X server: Composite local privilege escalation)


    Aaron Plattner discovered a buffer overflow in the compNewPixmap()
    function when copying data from a large pixel depth pixmap into a
    smaller pixel depth pixmap.
  
Impact

    A local attacker could execute arbitrary code with the privileges of
    the user running the X server, typically root.
  
Workaround

    Disable the Composite extension by setting \' Option "Composite"
    "disable" \' in the Extensions section of xorg.conf.
    Note: This could affect the functionality of some applications.
  
');
script_set_attribute(attribute:'solution', value: '
    All X.Org X server users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-base/xorg-server-1.3.0.0-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4730');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200710-16.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200710-16] X.Org X server: Composite local privilege escalation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'X.Org X server: Composite local privilege escalation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "x11-base/xorg-server", unaffected: make_list("ge 1.3.0.0-r1"), vulnerable: make_list("lt 1.3.0.0-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
