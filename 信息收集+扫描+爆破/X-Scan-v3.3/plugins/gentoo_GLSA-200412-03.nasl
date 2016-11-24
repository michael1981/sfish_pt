# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-03.xml
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
 script_id(15913);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200412-03");
 script_cve_id("CVE-2004-1026");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200412-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200412-03
(imlib: Buffer overflows in image decoding)


    Pavel Kankovsky discovered that several overflows found in the
    libXpm library (see GLSA 200409-34) also applied to imlib. He also
    fixed a number of other potential flaws.
  
Impact

    A remote attacker could entice a user to view a carefully-crafted
    image file, which would potentially lead to execution of arbitrary code
    with the rights of the user viewing the image. This affects any program
    that makes use of the imlib library.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All imlib users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/imlib-1.9.14-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200409-34.xml');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1026');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200412-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200412-03] imlib: Buffer overflows in image decoding');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'imlib: Buffer overflows in image decoding');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/imlib", unaffected: make_list("ge 1.9.14-r3"), vulnerable: make_list("le 1.9.14-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
