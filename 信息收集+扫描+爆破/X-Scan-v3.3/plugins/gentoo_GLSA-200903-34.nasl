# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200903-34.xml
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
 script_id(35985);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200903-34");
 script_cve_id("CVE-2009-0135", "CVE-2009-0136");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200903-34 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200903-34
(Amarok: User-assisted execution of arbitrary code)


    Tobias Klein has discovered multiple vulnerabilities in Amarok:
    Multiple integer overflows in the Audible::Tag::readTag()
    function in metadata/audible/audibletag.cpp trigger heap-based buffer
    overflows (CVE-2009-0135).
    Multiple array index errors in the
    Audible::Tag::readTag() function in metadata/audible/audibletag.cpp can
    lead to invalid pointer dereferences, or the writing of a 0x00 byte to
    an arbitrary memory location after an allocation failure
    (CVE-2009-0136).
  
Impact

    A remote attacker could entice a user to open a specially crafted
    Audible Audio (.aa) file with a large "nlen" or "vlen" tag value to
    execute arbitrary code or cause a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Amarok users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-sound/amarok-1.4.10-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0135');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0136');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200903-34.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200903-34] Amarok: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Amarok: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-sound/amarok", unaffected: make_list("ge 1.4.10-r2"), vulnerable: make_list("lt 1.4.10-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
