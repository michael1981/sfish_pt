# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-14.xml
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
 script_id(20235);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200511-14");
 script_cve_id("CVE-2005-2975", "CVE-2005-2976", "CVE-2005-3186");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200511-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200511-14
(GTK+ 2, GdkPixbuf: Multiple XPM decoding vulnerabilities)


    iDEFENSE reported a possible heap overflow in the XPM loader
    (CVE-2005-3186). Upon further inspection, Ludwig Nussel discovered two
    additional issues in the XPM processing functions : an integer overflow
    (CVE-2005-2976) that affects only gdk-pixbuf, and an infinite loop
    (CVE-2005-2975).
  
Impact

    Using a specially crafted XPM image an attacker could cause an
    affected application to enter an infinite loop or trigger the
    overflows, potentially allowing the execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All GTK+ 2 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose x11-libs/gtk+
    All GdkPixbuf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/gdk-pixbuf-0.22.0-r5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2975');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2976');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3186');
script_set_attribute(attribute: 'see_also', value: 'http://www.idefense.com/application/poi/display?id=339&type=vulnerabilities');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200511-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200511-14] GTK+ 2, GdkPixbuf: Multiple XPM decoding vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GTK+ 2, GdkPixbuf: Multiple XPM decoding vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/gdk-pixbuf", unaffected: make_list("ge 0.22.0-r5"), vulnerable: make_list("lt 0.22.0-r5")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "x11-libs/gtk+", unaffected: make_list("ge 2.8.6-r1", "rge 2.6.10-r1", "lt 2.0"), vulnerable: make_list("lt 2.8.6-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
