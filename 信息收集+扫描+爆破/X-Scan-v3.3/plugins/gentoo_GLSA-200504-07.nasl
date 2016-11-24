# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-07.xml
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
 script_id(18001);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200504-07");
 script_cve_id("CVE-2005-0706");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200504-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200504-07
(GnomeVFS, libcdaudio: CDDB response overflow)


    Joseph VanAndel has discovered a buffer overflow in Grip when
    processing large CDDB results (see GLSA 200503-21). The same overflow
    is present in GnomeVFS and libcdaudio code.
  
Impact

    A malicious CDDB server could cause applications making use of GnomeVFS
    or libcdaudio libraries to crash, potentially allowing the execution of
    arbitrary code with the privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All GnomeVFS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose gnome-base/gnome-vfs
    All libcdaudio users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/libcdaudio-0.99.10-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0706');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200503-21.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200504-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200504-07] GnomeVFS, libcdaudio: CDDB response overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GnomeVFS, libcdaudio: CDDB response overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/libcdaudio", unaffected: make_list("ge 0.99.10-r1"), vulnerable: make_list("lt 0.99.10-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "gnome-base/gnome-vfs", unaffected: make_list("ge 2.8.4-r1", "rge 1.0.5-r4"), vulnerable: make_list("lt 2.8.4-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
