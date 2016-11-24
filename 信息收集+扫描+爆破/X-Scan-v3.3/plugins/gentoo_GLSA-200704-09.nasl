# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200704-09.xml
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
 script_id(25054);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200704-09");
 script_cve_id("CVE-2007-1246");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200704-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200704-09
(xine-lib: Heap-based buffer overflow)


    xine-lib does not check boundaries on data being read into buffers from
    DMO video files in code that is shared with MPlayer
    (DMO_VideoDecoder.c).
  
Impact

    An attacker could entice a user to play a specially crafted DMO video
    file with a player using xine-lib, potentially resulting in the
    execution of arbitrary code with the privileges of the user running the
    player.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All xine-lib users on the x86 platform should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/xine-lib-1.1.4-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1246');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200704-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200704-09] xine-lib: Heap-based buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'xine-lib: Heap-based buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/xine-lib", arch: "x86", unaffected: make_list("ge 1.1.4-r2"), vulnerable: make_list("lt 1.1.4-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
