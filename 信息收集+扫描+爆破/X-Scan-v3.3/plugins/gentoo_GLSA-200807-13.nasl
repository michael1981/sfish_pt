# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200807-13.xml
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
 script_id(33779);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200807-13");
 script_cve_id("CVE-2008-2147", "CVE-2008-2430");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200807-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200807-13
(VLC: Multiple vulnerabilities)


    Remi Denis-Courmont reported that VLC loads plugins from the
    current working directory in an unsafe manner (CVE-2008-2147).
    Alin Rad Pop (Secunia Research) reported an integer overflow error
    in the Open() function in the file modules/demux/wav.c
    (CVE-2008-2430).
  
Impact

    A remote attacker could entice a user to open a specially crafted .wav
    file, and a local attacker could entice a user to run VLC from a
    directory containing specially crafted modules, possibly resulting in
    the execution of arbitrary code with the privileges of the user running
    the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All VLC users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/vlc-0.8.6i"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2147');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2430');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200807-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200807-13] VLC: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'VLC: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-video/vlc", unaffected: make_list("ge 0.8.6i"), vulnerable: make_list("lt 0.8.6i")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
