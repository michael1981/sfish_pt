# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-17.xml
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
 script_id(18089);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200504-17");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200504-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200504-17
(XV: Multiple vulnerabilities)


    Greg Roelofs has reported multiple input validation errors in XV
    image decoders. Tavis Ormandy of the Gentoo Linux Security Audit Team
    has reported insufficient validation in the PDS (Planetary Data System)
    image decoder, format string vulnerabilities in the TIFF and PDS
    decoders, and insufficient protection from shell meta-characters in
    malformed filenames.
  
Impact

    Successful exploitation would require a victim to view a specially
    created image file using XV, potentially resulting in the execution of
    arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All XV users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/xv-3.10a-r11"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200504-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200504-17] XV: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'XV: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-gfx/xv", unaffected: make_list("ge 3.10a-r11"), vulnerable: make_list("lt 3.10a-r11")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
