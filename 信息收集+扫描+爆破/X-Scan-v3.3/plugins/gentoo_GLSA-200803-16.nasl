# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200803-16.xml
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
 script_id(31442);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200803-16");
 script_cve_id("CVE-2008-0485", "CVE-2008-0486", "CVE-2008-0629", "CVE-2008-0630");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200803-16 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200803-16
(MPlayer: Multiple buffer overflows)


    The following errors have been discovered in MPlayer:
    Felipe Manzano and Anibal Sacco (Core Security Technologies)
    reported an array indexing error in the file libmpdemux/demux_mov.c
    when parsing MOV file headers (CVE-2008-0485).
    Damian Frizza
    and Alfredo Ortega (Core Security Technologies) reported a boundary
    error in the file libmpdemux/demux_audio.c when parsing FLAC comments
    (CVE-2008-0486).
    Adam Bozanich (Mu Security) reported boundary
    errors in the cddb_parse_matches_list() and cddb_query_parse()
    functions in the file stream_cddb.c when parsing CDDB album titles
    (CVE-2008-0629) and in the url_scape_string() function in the file
    stream/url.c when parsing URLS (CVE-2008-0630).
  
Impact

    A remote attacker could entice a user to open a specially crafted file,
    possibly resulting in the execution of arbitrary code with the
    privileges of the user running MPlayer.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All MPlayer users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/mplayer-1.0_rc2_p25993"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0485');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0486');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0629');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0630');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200803-16.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200803-16] MPlayer: Multiple buffer overflows');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MPlayer: Multiple buffer overflows');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-video/mplayer", unaffected: make_list("ge 1.0_rc2_p25993"), vulnerable: make_list("lt 1.0_rc2_p25993")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
