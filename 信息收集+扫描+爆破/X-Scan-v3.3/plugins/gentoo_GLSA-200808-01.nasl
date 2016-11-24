# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200808-01.xml
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
 script_id(33831);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200808-01");
 script_cve_id("CVE-2008-0073", "CVE-2008-1482", "CVE-2008-1878");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200808-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200808-01
(xine-lib: User-assisted execution of arbitrary code)


    Multiple vulnerabilities have been discovered in xine-lib:
    Alin Rad Pop of Secunia reported an array indexing vulnerability in the
    sdpplin_parse() function in the file input/libreal/sdpplin.c when
    processing streams from RTSP servers that contain a large "streamid"
    SDP parameter (CVE-2008-0073).
    Luigi Auriemma reported multiple integer overflows that result in
    heap-based buffer overflows when processing ".FLV", ".MOV" ".RM",
    ".MVE", ".MKV", and ".CAK" files (CVE-2008-1482).
    Guido Landi reported a stack-based buffer overflow in the
    demux_nsf_send_chunk() function when handling titles within NES Music
    (.NSF) files (CVE-2008-1878).
  
Impact

    A remote attacker could entice a user to play a specially crafted video
    file or stream with a player using xine-lib, potentially resulting in
    the execution of arbitrary code with the privileges of the user running
    the player.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All xine-lib users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/xine-lib-1.1.13"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0073');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1482');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1878');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200808-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200808-01] xine-lib: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'xine-lib: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/xine-lib", unaffected: make_list("ge 1.1.13"), vulnerable: make_list("lt 1.1.13")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
