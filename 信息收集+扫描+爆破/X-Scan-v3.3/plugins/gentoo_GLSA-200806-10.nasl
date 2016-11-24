# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200806-10.xml
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
 script_id(33246);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200806-10");
 script_cve_id("CVE-2008-1806", "CVE-2008-1807", "CVE-2008-1808");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200806-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200806-10
(FreeType: User-assisted execution of arbitrary code)


    Regenrecht reported multiple vulnerabilities in FreeType via iDefense:
    An integer overflow when parsing values in the Private dictionary table
    in a PFB file, leading to a heap-based buffer overflow
    (CVE-2008-1806).
    An invalid free() call related to parsing an invalid "number of axes"
    field in a PFB file (CVE-2008-1807).
    Multiple off-by-one errors when parsing PBF and TTF files, leading to
    heap-based buffer overflows (CVE-2008-1808).
  
Impact

    A remote attacker could entice a user to open a specially crafted TTF
    or PBF file, possibly resulting in the execution of arbitrary code with
    the privileges of the user running an application linked against
    FreeType (such as the X.org X server, running as root).
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All FreeType users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/freetype-2.3.6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1806');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1807');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1808');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200806-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200806-10] FreeType: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'FreeType: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/freetype", unaffected: make_list("ge 2.3.6", "rge 1.4_pre20080316-r1"), vulnerable: make_list("lt 2.3.6")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
