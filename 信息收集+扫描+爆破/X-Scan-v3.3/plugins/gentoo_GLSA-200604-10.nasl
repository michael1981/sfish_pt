# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200604-10.xml
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
 script_id(21256);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200604-10");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200604-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200604-10
(zgv, xzgv: Heap overflow)


    Andrea Barisani of Gentoo Linux discovered xzgv and zgv allocate
    insufficient memory when rendering images with more than 3 output
    components, such as images using the YCCK or CMYK colour space. When
    xzgv or zgv attempt to render the image, data from the image overruns a
    heap allocated buffer.
  
Impact

    An attacker may be able to construct a malicious image that executes
    arbitrary code with the permissions of the xzgv or zgv user when
    attempting to render the image.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All xzgv users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/xzgv-0.8-r2"
    All zgv users should also upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/zgv-5.9"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1060');
script_set_attribute(attribute: 'see_also', value: 'http://www.svgalib.org/rus/zgv/');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200604-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200604-10] zgv, xzgv: Heap overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'zgv, xzgv: Heap overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-gfx/zgv", unaffected: make_list("ge 5.9"), vulnerable: make_list("lt 5.9")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "media-gfx/xzgv", unaffected: make_list("ge 0.8-r2"), vulnerable: make_list("lt 0.8-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
