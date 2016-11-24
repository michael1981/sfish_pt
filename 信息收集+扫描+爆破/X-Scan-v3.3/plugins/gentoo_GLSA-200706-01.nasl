# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200706-01.xml
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
 script_id(25438);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200706-01");
 script_cve_id("CVE-2007-2645");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200706-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200706-01
(libexif: Integer overflow vulnerability)


    Victor Stinner reported an integer overflow in the
    exif_data_load_data_entry() function from file exif-data.c while
    handling Exif data.
  
Impact

    An attacker could entice a user to process a file with specially
    crafted Exif extensions with an application making use of libexif,
    which will trigger the integer overflow and potentially execute
    arbitrary code or crash the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All libexif users should upgrade to the latest version. Please note
    that users upgrading from "<=media-libs/libexif-0.6.13" should also run
    revdep-rebuild after their upgrade.
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/libexif-0.6.15"
    # revdep-rebuild --library=/usr/lib/libexif.so
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2645');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200706-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200706-01] libexif: Integer overflow vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libexif: Integer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/libexif", unaffected: make_list("ge 0.6.15"), vulnerable: make_list("lt 0.6.15")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
