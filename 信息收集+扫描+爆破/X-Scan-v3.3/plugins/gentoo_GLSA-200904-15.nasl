# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200904-15.xml
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
 script_id(36176);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200904-15");
 script_cve_id("CVE-2009-1301");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200904-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200904-15
(mpg123: User-assisted execution of arbitrary code)


    The vendor reported a signedness error in the store_id3_text() function
    in id3.c, allowing for out-of-bounds memory access.
  
Impact

    A remote attacker could entice a user to open an MPEG-1 Audio Layer 3
    (MP3) file containing a specially crafted ID3 tag, possibly resulting
    in the execution of arbitrary code with the privileges of the user
    running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All mpg123 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-sound/mpg123-1.7.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1301');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200904-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200904-15] mpg123: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'mpg123: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-sound/mpg123", unaffected: make_list("ge 1.7.2"), vulnerable: make_list("lt 1.7.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
