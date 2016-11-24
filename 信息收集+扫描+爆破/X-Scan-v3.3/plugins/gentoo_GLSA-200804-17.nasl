# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200804-17.xml
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
 script_id(32010);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200804-17");
 script_cve_id("CVE-2008-1686");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200804-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200804-17
(Speex: User-assisted execution of arbitrary code)


    oCERT reported that the Speex library does not properly validate the
    "mode" value it derives from Speex streams, allowing for array indexing
    vulnerabilities inside multiple player applications. Within Gentoo,
    xine-lib, VLC, gst-plugins-speex from the GStreamer Good Plug-ins,
    vorbis-tools, libfishsound, Sweep, SDL_sound, and speexdec were found
    to be vulnerable.
  
Impact

    A remote attacker could entice a user to open a specially crafted Speex
    file or network stream with an application listed above. This might
    lead to the execution of arbitrary code with privileges of the user
    playing the file.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Speex users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/speex-1.2_beta3_p2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1686');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200804-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200804-17] Speex: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Speex: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/speex", unaffected: make_list("ge 1.2_beta3_p2"), vulnerable: make_list("lt 1.2_beta3_p2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
