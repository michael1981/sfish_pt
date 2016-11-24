# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-07.xml
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
 script_id(14661);
 script_version("$Revision: 1.8 $");
 script_xref(name: "GLSA", value: "200409-07");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200409-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200409-07
(xv: Buffer overflows in image handling)


    Multiple buffer overflow and integer handling vulnerabilities have been
    discovered in xv\'s image processing code. These vulnerabilities have been
    found in the xvbmp.c, xviris.c, xvpcx.c and xvpm.c source files.
  
Impact

    An attacker might be able to embed malicious code into an image, which
    would lead to the execution of arbitrary code under the privileges of the
    user viewing the image.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All xv users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=media-gfx/xv-3.10a-r7"
    # emerge ">=media-gfx/xv-3.10a-r7"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.securityfocus.com/archive/1/372345/2004-08-15/2004-08-21/0');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0802');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200409-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200409-07] xv: Buffer overflows in image handling');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'xv: Buffer overflows in image handling');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-gfx/xv", unaffected: make_list("ge 3.10a-r7"), vulnerable: make_list("lt 3.10a-r7")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
