# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-02.xml
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
 script_id(14535);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200407-02");
 script_cve_id("CVE-2004-0109", "CVE-2004-0133", "CVE-2004-0177", "CVE-2004-0178", "CVE-2004-0181", "CVE-2004-0228", "CVE-2004-0229", "CVE-2004-0394", "CVE-2004-0427", "CVE-2004-0495", "CVE-2004-0535", "CVE-2004-0554", "CVE-2004-1983");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200407-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200407-02
(Linux Kernel: Multiple vulnerabilities)

Impact

    Arbitrary code with normal non-super-user privileges may be able to
    exploit any of these vulnerabilities; gaining kernel level access to
    memory structures and hardware devices. This may be used for further
    exploitation of the system, to leak sensitive data or to cause a Denial
    of Service on the affected kernel.
  
Workaround

    Although users may not be affected by certain vulnerabilities, all
    kernels are affected by the CAN-2004-0394, CAN-2004-0427 and
    CAN-2004-0554 issues which have no workaround. As a result, all users
    are urged to upgrade their kernels to patched versions.
  

');
script_set_attribute(attribute:'solution', value: '
    Users are encouraged to upgrade to the latest available sources for
    their system:
    # emerge sync
    # emerge -pv your-favorite-sources
    # emerge your-favorite-sources
    # # Follow usual procedure for compiling and installing a kernel.
    # # If you use genkernel, run genkernel as you would do normally.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0109');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0133');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0177');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0178');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0181');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0228');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0229');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0394');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0427');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0495');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0535');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0554');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1983');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200407-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200407-02] Linux Kernel: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Linux Kernel: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sys-kernel/rsbac-sources", unaffected: make_list("ge 2.4.26-r2"), vulnerable: make_list("lt 2.4.26-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/hppa-dev-sources", unaffected: make_list("ge 2.6.7"), vulnerable: make_list("lt 2.6.7")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/hppa-sources", unaffected: make_list("ge 2.4.26_p6"), vulnerable: make_list("lt 2.4.26_p6")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/planet-ccrma-sources", unaffected: make_list("ge 2.4.21-r10"), vulnerable: make_list("lt 2.4.21-r10")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/openmosix-sources", unaffected: make_list("ge 2.4.22-r10"), vulnerable: make_list("lt 2.4.22-r10")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/vserver-sources", unaffected: make_list("ge 2.4.26.1.3.9-r2"), vulnerable: make_list("lt 2.4.26.1.3.9-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/development-sources", unaffected: make_list("ge 2.6.7"), vulnerable: make_list("lt 2.6.7")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/xbox-sources", unaffected: make_list("ge 2.6.7"), vulnerable: make_list("lt 2.6.7")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/hardened-dev-sources", unaffected: make_list("ge 2.6.7"), vulnerable: make_list("lt 2.6.7")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/gentoo-dev-sources", unaffected: make_list("ge 2.6.7"), vulnerable: make_list("lt 2.6.7")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/mips-sources", unaffected: make_list("ge 2.4.26-r3"), vulnerable: make_list("lt 2.4.26-r3")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/compaq-sources", unaffected: make_list("ge 2.4.9.32.7-r7"), vulnerable: make_list("lt 2.4.9.32.7-r7")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/pegasos-sources", unaffected: make_list("ge 2.4.26-r2"), vulnerable: make_list("lt 2.4.26-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/grsec-sources", unaffected: make_list("ge 2.4.26.2.0-r5"), vulnerable: make_list("lt 2.4.26.2.0-r5")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/uclinux-sources", unaffected: make_list("ge 2.4.26_p0-r2"), vulnerable: make_list("lt 2.4.26_p0-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/gaming-sources", unaffected: make_list("ge 2.4.20-r14"), vulnerable: make_list("lt 2.4.20-r14")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/wolk-sources", unaffected: make_list("rge 4.9-r9", "rge 4.11-r6", "ge 4.14-r3"), vulnerable: make_list("lt 4.14-r3")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/vanilla-sources", unaffected: make_list("ge 2.4.27"), vulnerable: make_list("le 2.4.26")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/gentoo-sources", unaffected: make_list("rge 2.4.19-r17", "rge 2.4.20-r20", "rge 2.4.22-r12", "rge 2.4.25-r5", "ge 2.4.26-r3"), vulnerable: make_list("lt 2.4.26-r3")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/aa-sources", unaffected: make_list("eq 2.4.23-r2"), vulnerable: make_list("lt 2.4.23-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/hardened-sources", unaffected: make_list("ge 2.4.26-r2"), vulnerable: make_list("lt 2.4.26-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/gs-sources", unaffected: make_list("ge 2.4.25_pre7-r7"), vulnerable: make_list("lt 2.4.25_pre7-r7")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/ia64-sources", unaffected: make_list("ge 2.4.24-r5"), vulnerable: make_list("lt 2.4.24-r5")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/pac-sources", unaffected: make_list("ge 2.4.23-r8"), vulnerable: make_list("lt 2.4.23-r8")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/pegasos-dev-sources", unaffected: make_list("ge 2.6.7"), vulnerable: make_list("lt 2.6.7")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/ppc64-sources", unaffected: make_list("ge 2.6.7"), vulnerable: make_list("lt 2.6.7")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/alpha-sources", unaffected: make_list("ge 2.4.21-r8"), vulnerable: make_list("lt 2.4.21-r8")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/sparc-sources", unaffected: make_list("ge 2.4.26-r2"), vulnerable: make_list("lt 2.4.26-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/xfs-sources", unaffected: make_list("ge 2.4.24-r8"), vulnerable: make_list("lt 2.4.24-r8")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/ppc-sources", unaffected: make_list("ge 2.4.26-r2"), vulnerable: make_list("lt 2.4.26-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/rsbac-dev-sources", unaffected: make_list("ge 2.6.7-r1"), vulnerable: make_list("lt 2.6.7-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/selinux-sources", unaffected: make_list("ge 2.4.26-r2"), vulnerable: make_list("lt 2.4.26-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/usermode-sources", unaffected: make_list("rge 2.4.24-r5", "ge 2.4.26-r2"), vulnerable: make_list("lt 2.4.26-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/ck-sources", unaffected: make_list("eq 2.4.26-r1", "ge 2.6.7-r1"), vulnerable: make_list("lt 2.6.7-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/win4lin-sources", unaffected: make_list("ge 2.4.26-r2"), vulnerable: make_list("lt 2.4.26-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/mm-sources", unaffected: make_list("ge 2.6.7-r1"), vulnerable: make_list("lt 2.6.7-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
