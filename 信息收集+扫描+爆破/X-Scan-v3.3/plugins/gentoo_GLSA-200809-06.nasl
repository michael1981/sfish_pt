# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200809-06.xml
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
 script_id(34105);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200809-06");
 script_cve_id("CVE-2008-3732", "CVE-2008-3794");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200809-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200809-06
(VLC: Multiple vulnerabilities)


    g_ reported the following vulnerabilities:
    An integer
    overflow leading to a heap-based buffer overflow in the Open() function
    in modules/demux/tta.c (CVE-2008-3732).
    A signedness error
    leading to a stack-based buffer overflow in the mms_ReceiveCommand()
    function in modules/access/mms/mmstu.c (CVE-2008-3794).
  
Impact

    A remote attacker could entice a user to open a specially crafted file,
    possibly resulting in the remote execution of arbitrary code with the
    privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All VLC users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/vlc-0.8.6i-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3732');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3794');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200809-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200809-06] VLC: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'VLC: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-video/vlc", unaffected: make_list("ge 0.8.6i-r2"), vulnerable: make_list("lt 0.8.6i-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
