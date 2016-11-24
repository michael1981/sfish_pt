# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200812-11.xml
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
 script_id(35086);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200812-11");
 script_cve_id("CVE-2008-3639", "CVE-2008-3640", "CVE-2008-3641", "CVE-2008-5286");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200812-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200812-11
(CUPS: Multiple vulnerabilities)


    Several buffer overflows were found in:
    The read_rle16 function in imagetops (CVE-2008-3639, found by
    regenrecht, reported via ZDI)
    The WriteProlog function in texttops (CVE-2008-3640, found by
    regenrecht, reported via ZDI)
    The Hewlett-Packard Graphics Language (HPGL) filter (CVE-2008-3641,
    found by regenrecht, reported via iDefense)
    The _cupsImageReadPNG function (CVE-2008-5286, reported by iljavs)
  
Impact

    A remote attacker could send specially crafted input to a vulnerable
    server, resulting in the remote execution of arbitrary code with the
    privileges of the user running the server.
  
Workaround

    None this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All CUPS users should upgrade to the latest version.
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-print/cups-1.3.9-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3639');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3640');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3641');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5286');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200812-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200812-11] CUPS: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'CUPS: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-print/cups", unaffected: make_list("ge 1.3.9-r1"), vulnerable: make_list("lt 1.3.9-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
