
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27295);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  Linux Kernel security update (kernel-3760)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-3760");
 script_set_attribute(attribute: "description", value: "This kernel update fixes the following security problems:

- CVE-2007-1861: The nl_fib_lookup function in
  net/ipv4/fib_frontend.c allows attackers to cause a
  denial of service (kernel panic) via NETLINK_FIB_LOOKUP
  replies, which trigger infinite recursion and a stack
  overflow.

- CVE-2007-1496: nfnetlink_log in netfilter allows
  attackers to cause a denial of service (crash) via
  unspecified vectors involving the (1) nfulnl_recv_config
  function, (2) using 'multiple packets per netlink
  message', and (3) bridged packets, which trigger a NULL
  pointer dereference.

- CVE-2007-1497: nf_conntrack in netfilter does not set
  nfctinfo during reassembly of fragmented packets, which
  leaves the default value as IP_CT_ESTABLISHED and might
  allow remote attackers to bypass certain rulesets using
  IPv6 fragments.

                 Please note that the connection tracking
option for IPv6 is not enabled in any currently shipping
SUSE Linux kernel, so it does not affect SUSE Linux default
kernels.

- CVE-2007-2242: The IPv6 protocol allows remote attackers
  to cause a denial of service via crafted IPv6 type 0
  route headers (IPV6_RTHDR_TYPE_0) that create network
  amplification between two routers.

                 The behaviour has been disabled by
default, and the patch introduces a new sysctl with which
the administrator can reenable it again.

- CVE-2006-7203: The compat_sys_mount function in
  fs/compat.c allows local users to cause a denial of
  service (NULL pointer dereference and oops) by mounting a
  smbfs file system in compatibility mode ('mount -t
  smbfs').

- CVE-2007-2453: Seeding of the kernel random generator on
  boot did not work correctly due to a programming mistake
  and so the kernel might have more predictable random
  numbers than assured.

- CVE-2007-2876: A NULL pointer dereference in SCTP
  connection tracking could be caused by a remote attacker
  by sending specially crafted packets. Note that this
  requires SCTP set-up and active to be exploitable.


and the following non security bugs:

- - patches.fixes/cpufreq_fix_limited_on_battery.patch: Fix
  limited freq when booted on battery.  [#231107]
- - patches.fixes/usb-keyspan-regression-fix.patch: USB:
  keyspan regression fix  [#240919]
- -
patches.fixes/hpt366-dont-check-enablebits-for-hpt36x.patch:
   hpt366: don't check enablebits for HPT36x  [#278696]
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-3760");
script_end_attributes();

script_cve_id("CVE-2007-1861", "CVE-2007-1496", "CVE-2007-1497", "CVE-2007-2242", "CVE-2006-7203", "CVE-2007-2453", "CVE-2007-2876");
script_summary(english: "Check for the kernel-3760 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kernel-bigsmp-2.6.18.8-0.5", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.18.8-0.5", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-iseries64-2.6.18.8-0.5", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-ppc64-2.6.18.8-0.5", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.18.8-0.5", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.18.8-0.5", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18.8-0.5", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.18.8-0.5", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
