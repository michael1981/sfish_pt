# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200804-01.xml
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
 script_id(31752);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200804-01");
 script_cve_id("CVE-2008-0047", "CVE-2008-0053", "CVE-2008-0882", "CVE-2008-1373");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200804-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200804-01
(CUPS: Multiple vulnerabilities)


    Multiple vulnerabilities have been reported in CUPS:
    regenrecht (VeriSign iDefense) discovered that the
    cgiCompileSearch() function used in several CGI scripts in CUPS\'
    administration interface does not correctly calculate boundaries when
    processing a user-provided regular expression, leading to a heap-based
    buffer overflow (CVE-2008-0047).
    Helge Blischke reported a
    double free() vulnerability in the process_browse_data() function when
    adding or removing remote shared printers (CVE-2008-0882).
    Tomas Hoger (Red Hat) reported that the gif_read_lzw() function
    uses the code_size value from GIF images without properly checking it,
    leading to a buffer overflow (CVE-2008-1373).
    An unspecified
    input validation error was discovered in the HP-GL/2 filter
    (CVE-2008-0053).
  
Impact

    A local attacker could send specially crafted network packets or print
    jobs and possibly execute arbitrary code with the privileges of the
    user running CUPS (usually lp), or cause a Denial of Service. The
    vulnerabilities are exploitable via the network when CUPS is sharing
    printers remotely.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All CUPS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-print/cups-1.2.12-r7"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0047');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0053');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0882');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1373');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200804-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200804-01] CUPS: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'CUPS: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-print/cups", unaffected: make_list("ge 1.2.12-r7"), vulnerable: make_list("lt 1.2.12-r7")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
