# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200402-06.xml
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
 script_id(14450);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200402-06");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200402-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200402-06
(Updated kernel packages fix the AMD64 ptrace vulnerability)


    A vulnerability has been discovered by Andi Kleen in the ptrace emulation
    code for AMD64 platforms when eflags are processed, allowing a local user
    to obtain elevated priveleges.  The Common Vulnerabilities and Exposures
    project, http://cve.mitre.org, has assigned CAN-2004-0001 to this issue.
  
Impact

    Only users of the AMD64 platform are affected: in this scenario, a user may
    be able to obtain elevated priveleges, including root access. However, no
    public exploit is known for the vulnerability at this time.
  
Workaround

    There is no temporary workaround - a kernel upgrade is required. A list of
    unaffected kernels is provided along with this announcement.
  
');
script_set_attribute(attribute:'solution', value: '
    Users are encouraged to upgrade to the latest available sources for
    their system:
    # emerge sync
    # emerge -pv your-favourite-sources
    # emerge your-favourite-sources
    # # Follow usual procedure for compiling and installing a kernel.
    # # If you use genkernel, run genkernel as you would do normally.
    # # IF YOUR KERNEL IS MARKED as "remerge required!" THEN
    # # YOU SHOULD UPDATE YOUR KERNEL EVEN IF PORTAGE
    # # REPORTS THAT THE SAME VERSION IS INSTALLED.
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200402-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200402-06] Updated kernel packages fix the AMD64 ptrace vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Updated kernel packages fix the AMD64 ptrace vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sys-kernel/gs-sources", arch: "amd64", unaffected: make_list("ge 2.4.25_pre7-r1"), vulnerable: make_list("lt 2.4.25_pre7-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/gentoo-test-sources", arch: "amd64", unaffected: make_list("ge 2.6.2-r1"), vulnerable: make_list("lt 2.6.2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/development-sources", arch: "amd64", unaffected: make_list("ge 2.6.2"), vulnerable: make_list("lt 2.6.2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/ck-sources", arch: "amd64", unaffected: make_list("ge 2.6.2"), vulnerable: make_list("lt 2.6.2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/gentoo-dev-sources", arch: "amd64", unaffected: make_list("ge 2.6.2"), vulnerable: make_list("lt 2.6.2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/vanilla-prepatch-sources", arch: "amd64", unaffected: make_list("ge 2.4.25_rc3"), vulnerable: make_list("lt 2.4.25_rc3")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/gentoo-sources", arch: "amd64", unaffected: make_list("ge 2.4.22-r6"), vulnerable: make_list("lt 2.4.22-r6")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/vanilla-sources", arch: "amd64", unaffected: make_list("ge 2.4.24-r1"), vulnerable: make_list("lt 2.4.24-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
