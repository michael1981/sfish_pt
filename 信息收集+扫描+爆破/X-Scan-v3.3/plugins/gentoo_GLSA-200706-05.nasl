# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200706-05.xml
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
 script_id(25534);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200706-05");
 script_cve_id("CVE-2007-2650", "CVE-2007-3023", "CVE-2007-3024", "CVE-2007-3122", "CVE-2007-3123");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200706-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200706-05
(ClamAV: Multiple Denials of Service)


    Several vulnerabilities were discovered in ClamAV by various
    researchers:
    Victor Stinner (INL) discovered that the OLE2
    parser may enter in an infinite loop (CVE-2007-2650).
    A
    boundary error was also reported by an anonymous researcher in the file
    unsp.c, which might lead to a buffer overflow (CVE-2007-3023).
    The file unrar.c contains a heap-based buffer overflow via a
    modified vm_codesize value from a RAR file (CVE-2007-3123).
    The RAR parsing engine can be bypassed via a RAR file with a header
    flag value of 10 (CVE-2007-3122).
    The cli_gentempstream()
    function from clamdscan creates temporary files with insecure
    permissions (CVE-2007-3024).
  
Impact

    A remote attacker could send a specially crafted file to the scanner,
    possibly triggering one of the vulnerabilities. The two buffer
    overflows are reported to only cause Denial of Service. This would lead
    to a Denial of Service by CPU consumption or a crash of the scanner.
    The insecure temporary file creation vulnerability could be used by a
    local user to access sensitive data.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ClamAV users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-antivirus/clamav-0.90.3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2650');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3023');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3024');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3122');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3123');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200706-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200706-05] ClamAV: Multiple Denials of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ClamAV: Multiple Denials of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-antivirus/clamav", unaffected: make_list("ge 0.90.3"), vulnerable: make_list("lt 0.90.3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
