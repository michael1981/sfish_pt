# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200803-14.xml
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
 script_id(31440);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200803-14");
 script_cve_id("CVE-2008-0411");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200803-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200803-14
(Ghostscript: Buffer overflow)


    Chris Evans (Google Security) discovered a stack-based buffer overflow
    within the zseticcspace() function in the file zicc.c when processing a
    PostScript file containing a long "Range" array in a .seticcscpate
    operator.
  
Impact

    A remote attacker could exploit this vulnerability by enticing a user
    to open a specially crafted PostScript file, which could possibly lead
    to the execution of arbitrary code or a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Ghostscript ESP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/ghostscript-esp-8.15.4-r1"
    All Ghostscript GPL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/ghostscript-gpl-8.61-r3"
    All Ghostscript GNU users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/ghostscript-gnu-8.60.0-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0411');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200803-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200803-14] Ghostscript: Buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ghostscript: Buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/ghostscript-esp", unaffected: make_list("ge 8.15.4-r1"), vulnerable: make_list("lt 8.15.4-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-text/ghostscript-gpl", unaffected: make_list("ge 8.61-r3"), vulnerable: make_list("lt 8.61-r3")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-text/ghostscript-gnu", unaffected: make_list("ge 8.60.0-r2"), vulnerable: make_list("lt 8.60.0-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
