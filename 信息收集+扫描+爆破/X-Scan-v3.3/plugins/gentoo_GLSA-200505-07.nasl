# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-07.xml
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
 script_id(18233);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200505-07");
 script_cve_id("CVE-2005-1544");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200505-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200505-07
(libTIFF: Buffer overflow)


    Tavis Ormandy of the Gentoo Linux Security Audit Team discovered a
    stack based buffer overflow in the libTIFF library when reading a TIFF
    image with a malformed BitsPerSample tag.
  
Impact

    Successful exploitation would require the victim to open a specially
    crafted TIFF image, resulting in the execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All libTIFF users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/tiff-3.7.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://bugzilla.remotesensing.org/show_bug.cgi?id=843');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1544');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200505-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200505-07] libTIFF: Buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libTIFF: Buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/tiff", unaffected: make_list("ge 3.7.2"), vulnerable: make_list("lt 3.7.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
