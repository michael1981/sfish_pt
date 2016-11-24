# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-14.xml
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
 script_id(22200);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200608-14");
 script_cve_id("CVE-2006-3668");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200608-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200608-14
(DUMB: Heap buffer overflow)


    Luigi Auriemma found a heap-based buffer overflow in the
    it_read_envelope function which reads the envelope values for volume,
    pan and pitch of the instruments referenced in a ".it" (Impulse
    Tracker) file with a large number of nodes.
  
Impact

    By enticing a user to load a malicious ".it" (Impulse Tracker) file, an
    attacker may execute arbitrary code with the rights of the user running
    the application that uses a vulnerable DUMB library.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All users of DUMB should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/dumb-0.9.3-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3668');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200608-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200608-14] DUMB: Heap buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'DUMB: Heap buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/dumb", unaffected: make_list("ge 0.9.3-r1"), vulnerable: make_list("lt 0.9.3-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
