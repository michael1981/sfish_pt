# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200706-09.xml
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
 script_id(25594);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200706-09");
 script_cve_id("CVE-2006-4168");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200706-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200706-09
(libexif: Buffer overflow)


    iDefense Labs have discovered that the exif_data_load_data_entry()
    function in libexif/exif-data.c improperly handles integer data while
    working with an image with many EXIF components, allowing an integer
    overflow possibly leading to a heap-based buffer overflow.
  
Impact

    An attacker could entice a user of an application making use of a
    vulnerable version of libexif to load a specially crafted image file,
    possibly resulting in a crash of the application or the execution of
    arbitrary code with the rights of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All libexif users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/libexif-0.6.16"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4168');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200706-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200706-09] libexif: Buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libexif: Buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/libexif", unaffected: make_list("ge 0.6.16"), vulnerable: make_list("lt 0.6.16")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
