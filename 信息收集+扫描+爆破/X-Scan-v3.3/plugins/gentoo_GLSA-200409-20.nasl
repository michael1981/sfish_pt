# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-20.xml
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
 script_id(14747);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200409-20");
 script_cve_id("CVE-2004-0805");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200409-20 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200409-20
(mpg123: Buffer overflow vulnerability)


    mpg123 contains a buffer overflow in the code that handles layer2
    decoding of media files.
  
Impact

    An attacker can possibly exploit this bug with a specially-crafted mp3 or mp2 file
    to execute arbitrary code with the permissions of the user running mpg123.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All mpg123 users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=media-sound/mpg123-0.59s-r4"
    # emerge ">=media-sound/mpg123-0.59s-r4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.securityfocus.com/archive/1/374433/2004-09-05/2004-09-11/0');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0805');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200409-20.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200409-20] mpg123: Buffer overflow vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'mpg123: Buffer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-sound/mpg123", unaffected: make_list("ge 0.59s-r4"), vulnerable: make_list("le 0.59s-r3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
