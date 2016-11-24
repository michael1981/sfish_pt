# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200711-23.xml
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
 script_id(28262);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200711-23");
 script_cve_id("CVE-2004-0813", "CVE-2006-3619", "CVE-2006-4146", "CVE-2006-4600", "CVE-2007-0061", "CVE-2007-0062", "CVE-2007-0063", "CVE-2007-1716", "CVE-2007-4496", "CVE-2007-4497", "CVE-2007-5617");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200711-23 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200711-23
(VMware Workstation and Player: Multiple vulnerabilities)


    Multiple vulnerabilities have been discovered in several VMware
    products. Neel Mehta and Ryan Smith (IBM ISS X-Force) discovered that
    the DHCP server contains an integer overflow vulnerability
    (CVE-2007-0062), an integer underflow vulnerability (CVE-2007-0063) and
    another error when handling malformed packets (CVE-2007-0061), leading
    to stack-based buffer overflows or stack corruption. Rafal Wojtczvk
    (McAfee) discovered two unspecified errors that allow authenticated
    users with administrative or login privileges on a guest operating
    system to corrupt memory or cause a Denial of Service (CVE-2007-4496,
    CVE-2007-4497). Another unspecified vulnerability related to untrusted
    virtual machine images was discovered (CVE-2007-5617).
    VMware products also shipped code copies of software with several
    vulnerabilities: Samba (GLSA-200705-15), BIND (GLSA-200702-06), MIT
    Kerberos 5 (GLSA-200707-11), Vixie Cron (GLSA-200704-11), shadow
    (GLSA-200606-02), OpenLDAP (CVE-2006-4600), PAM (CVE-2004-0813,
    CVE-2007-1716), GCC (CVE-2006-3619) and GDB (CVE-2006-4146).
  
Impact

    Remote attackers within a guest system could possibly exploit these
    vulnerabilities to execute code on the host system with elevated
    privileges or to cause a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All VMware Workstation users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-emulation/vmware-workstation-5.5.5.56455"
    All VMware Player users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-emulation/vmware-player-1.0.5.56455"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0813');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3619');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4146');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4600');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0061');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0062');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0063');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1716');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4496');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4497');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5617');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200606-02.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200702-06.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200704-11.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200705-15.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200707-11.xml');
script_set_attribute(attribute: 'see_also', value: 'http://lists.vmware.com/pipermail/security-announce/2007/000001.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-23.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200711-23] VMware Workstation and Player: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'VMware Workstation and Player: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-emulation/vmware-workstation", unaffected: make_list("ge 5.5.5.56455"), vulnerable: make_list("lt 5.5.5.56455", "eq 6.0.0.45731")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-emulation/vmware-player", unaffected: make_list("ge 1.0.5.56455"), vulnerable: make_list("lt 1.0.5.56455", "eq 2.0.0.45731")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
