# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200903-31.xml
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
 script_id(35954);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200903-31");
 script_cve_id("CVE-2008-5030");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200903-31 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200903-31
(libcdaudio: User-assisted execution of arbitrary code)


    A heap-based buffer overflow has been reported in the
    cddb_read_disc_data() function in cddb.c when processing overly long
    CDDB data.
  
Impact

    A remote attacker could entice a user to connect to a malicious CDDB
    server, possibly resulting in the remote execution of arbitrary code
    with the privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All libcdaudio users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/libcdaudio-0.99.12-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5030');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200903-31.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200903-31] libcdaudio: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libcdaudio: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/libcdaudio", unaffected: make_list("ge 0.99.12-r1"), vulnerable: make_list("lt 0.99.12-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
