# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200805-19.xml
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
 script_id(32417);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200805-19");
 script_cve_id("CVE-2008-0314", "CVE-2008-1100", "CVE-2008-1387", "CVE-2008-1833", "CVE-2008-1835", "CVE-2008-1836", "CVE-2008-1837");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200805-19 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200805-19
(ClamAV: Multiple vulnerabilities)


    Multiple vulnerabilities have been reported:
    Damian Put reported a heap-based buffer overflow when processing PeSpin
    packed PE binaries (CVE-2008-0314).
    Alin Rad Pop of Secunia Research reported a buffer overflow in the
    cli_scanpe() function when processing Upack PE binaries
    (CVE-2008-1100).
    Hanno Boeck reported an infinite loop when processing ARJ archives
    (CVE-2008-1387).
    Damian Put and Thomas Pollet reported a heap-based buffer overflow when
    processing WWPack compressed PE binaries (CVE-2008-1833).
    A buffer over-read was discovered in the rfc2231() function when
    producing a string that is not NULL terminated (CVE-2008-1836).
    An unspecified vulnerability leading to "memory problems" when scanning
    RAR files was reported (CVE-2008-1837).
    Thierry Zoller reported that scanning of RAR files could be
    circumvented (CVE-2008-1835).
  
Impact

    A remote attacker could entice a user or automated system to scan a
    specially crafted file, possibly leading to the execution of arbitrary
    code with the privileges of the user running ClamAV (either a system
    user or the "clamav" user if clamd is compromised), or a Denial of
    Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ClamAV users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-antivirus/clamav-0.93"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0314');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1100');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1387');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1833');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1835');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1836');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1837');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200805-19.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200805-19] ClamAV: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ClamAV: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-antivirus/clamav", unaffected: make_list("ge 0.93"), vulnerable: make_list("lt 0.93")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
