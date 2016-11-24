# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200802-12.xml
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
 script_id(31295);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200802-12");
 script_cve_id("CVE-2006-1664", "CVE-2008-0486", "CVE-2008-1110");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200802-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200802-12
(xine-lib: User-assisted execution of arbitrary code)


    Damian Frizza and Alfredo Ortega (Core Security Technologies)
    discovered a stack-based buffer overflow within the open_flac_file()
    function in the file demux_flac.c when parsing tags within a FLAC file
    (CVE-2008-0486). A buffer overflow when parsing ASF headers, which is
    similar to CVE-2006-1664, has also been discovered (CVE-2008-1110).
  
Impact

    A remote attacker could entice a user to play specially crafted FLAC or
    ASF video streams with a player using xine-lib, potentially resulting
    in the execution of arbitrary code with the privileges of the user
    running the player.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All xine-lib users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/xine-lib-1.1.10.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1664');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0486');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1110');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200802-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200802-12] xine-lib: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'xine-lib: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/xine-lib", unaffected: make_list("ge 1.1.10.1"), vulnerable: make_list("lt 1.1.10.1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
