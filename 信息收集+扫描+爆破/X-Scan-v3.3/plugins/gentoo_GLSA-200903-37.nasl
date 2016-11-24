# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200903-37.xml
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
 script_id(36003);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200903-37");
 script_cve_id("CVE-2009-0583", "CVE-2009-0584");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200903-37 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200903-37
(Ghostscript: User-assisted execution of arbitrary code)


    Jan Lieskovsky from the Red Hat Security Response Team discovered the
    following vulnerabilities in Ghostscript\'s ICC Library:
    Multiple integer overflows (CVE-2009-0583).
    Multiple
    insufficient bounds checks on certain variable sizes
    (CVE-2009-0584).
  
Impact

    A remote attacker could entice a user to open a specially crafted
    PostScript file containing images and a malicious ICC profile, possibly
    resulting in the execution of arbitrary code with the privileges of the
    user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All GPL Ghostscript users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/ghostscript-gpl-8.64-r2"
    All GNU Ghostscript users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/ghostscript-gnu-8.62.0"
    We recommend that users unmerge ESP Ghostscript and use GPL or GNU
    Ghostscript instead:
    # emerge --unmerge "app-text/ghostscript-esp"
    For installation instructions, see above.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0583');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0584');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200903-37.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200903-37] Ghostscript: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ghostscript: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/ghostscript-esp", unaffected: make_list(), vulnerable: make_list("le 8.15.4-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-text/ghostscript-gpl", unaffected: make_list("ge 8.64-r2"), vulnerable: make_list("lt 8.64-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-text/ghostscript-gnu", unaffected: make_list("ge 8.62.0"), vulnerable: make_list("lt 8.62.0")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
