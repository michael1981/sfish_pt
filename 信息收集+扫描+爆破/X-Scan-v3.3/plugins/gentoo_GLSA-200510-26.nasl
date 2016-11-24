# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200510-26.xml
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
 script_id(21275);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200510-26");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200510-26 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200510-26
(XLI, Xloadimage: Buffer overflow)


    When XLI or Xloadimage process an image, they create a new image
    object to contain the new image, copying the title from the old image
    to the newly created image. Ariel Berkman reported that the \'zoom\',
    \'reduce\', and \'rotate\' functions use a fixed length buffer to contain
    the new title, which could be overwritten by the NIFF or XPM image
    processors.
  
Impact

    A malicious user could craft a malicious XPM or NIFF file and
    entice a user to view it using XLI, or manipulate it using Xloadimage,
    potentially resulting in the execution of arbitrary code with the
    permissions of the user running XLI or Xloadimage.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All XLI users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/xli-1.17.0-r2"
    All Xloadimage users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/xloadimage-4.1-r4"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-3178');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200510-26.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200510-26] XLI, Xloadimage: Buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'XLI, Xloadimage: Buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-gfx/xloadimage", unaffected: make_list("ge 4.1-r4"), vulnerable: make_list("lt 4.1-r4")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "media-gfx/xli", unaffected: make_list("ge 1.17.0-r2"), vulnerable: make_list("lt 1.17.0-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
