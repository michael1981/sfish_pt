# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200802-09.xml
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
 script_id(31157);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200802-09");
 script_cve_id("CVE-2008-0318", "CVE-2008-0728");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200802-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200802-09
(ClamAV: Multiple vulnerabilities)


    An integer overflow has been reported in the "cli_scanpe()" function in
    file libclamav/pe.c (CVE-2008-0318). Another unspecified vulnerability
    has been reported in file libclamav/mew.c (CVE-2008-0728).
  
Impact

    A remote attacker could entice a user or automated system to scan a
    specially crafted file, possibly leading to the execution of arbitrary
    code with the privileges of the user running ClamAV (either a system
    user or the "clamav" user if clamd is compromised).
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ClamAV users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-antivirus/clamav-0.92.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0318');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0728');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200802-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200802-09] ClamAV: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ClamAV: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-antivirus/clamav", unaffected: make_list("ge 0.92.1"), vulnerable: make_list("lt 0.92.1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
