# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200711-26.xml
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
 script_id(28265);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200711-26");
 script_cve_id("CVE-2007-5935", "CVE-2007-5936", "CVE-2007-5937");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200711-26 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200711-26
(teTeX: Multiple vulnerabilities)


    Joachim Schrod discovered several buffer overflow vulnerabilities and
    an insecure temporary file creation in the "dvilj" application that is
    used by dvips to convert DVI files to printer formats (CVE-2007-5937,
    CVE-2007-5936). Bastien Roucaries reported that the "dvips" application
    is vulnerable to two stack-based buffer overflows when processing DVI
    documents with long \\href{} URIs (CVE-2007-5935). teTeX also includes
    code from Xpdf that is vulnerable to a memory corruption and two
    heap-based buffer overflows (GLSA 200711-22); and it contains code from
    T1Lib that is vulnerable to a buffer overflow when processing an overly
    long font filename (GLSA 200710-12).
  
Impact

    A remote attacker could entice a user to process a specially crafted
    DVI or PDF file which could lead to the execution of arbitrary code
    with the privileges of the user running the application. A local
    attacker could exploit the "dvilj" vulnerability to conduct a symlink
    attack to overwrite arbitrary files.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All teTeX users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/tetex-3.0_p1-r6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5935');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5936');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5937');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200710-12.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-22.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-26.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200711-26] teTeX: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'teTeX: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/tetex", unaffected: make_list("ge 3.0_p1-r6"), vulnerable: make_list("lt 3.0_p1-r6")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
