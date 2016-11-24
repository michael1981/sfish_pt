
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27294);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  Linux Kernel security update (kernel-3128)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-3128");
 script_set_attribute(attribute: "description", value: "This kernel update fixes the following security problems:

- CVE-2007-1000   A NULL pointer dereference in the IPv6
  sockopt handling can be used by local attackers to read
  arbitrary kernel memory and so gain access to private
  information.

- CVE-2007-1388   A NULL pointer dereference could be used
  by local attackers to cause a Oops / crash of the machine.

- CVE-2007-1592   A possible double free in the
  ipv6/flowlabel handling was fixed.

- CVE-2007-1357   A remote denial of service attack in the
  AppleTalk protocol handler was fixed. This attack is only
  possible on the local subnet, and requires the AppleTalk
  protocol module to be loaded (which is not done by
  default).

and the following non security bugs:

- patches.fixes/visor_write_race.patch: fix race allowing
  overstepping memory limit in visor_write (Mainline:
  2.6.21)
- patches.drivers/libata-ide-via-add-PCI-IDs:
  via82cxxx/pata_via:  backport PCI IDs (254158).
- libata:  implement HDIO_GET_IDENTITY (255413).
- sata_sil24:  Add Adaptec 1220SA PCI ID. (Mainline: 2.6.21)
- ide:  backport hpt366 from devel tree (244502).
- mm:  fix madvise infinine loop (248167).
- libata:  hardreset on SERR_INTERNAL (241334).
- limited WPA support for prism54 (207944)
- jmicron: match class instead of function number (224784,
  207707)
- ahci: RAID mode SATA patch for Intel ICH9M (Mainline:
  2.6.21)
- libata: blacklist FUJITSU MHT2060BH for NCQ (Mainline:
  2.6.21)
- libata: add missing PM callbacks. (Mainline: 2.6.20)
- patches.fixes/nfs-readdir-timestamp: Set meaningful value
  for fattr->time_start in readdirplus results. (244967).
- patches.fixes/usb_volito.patch: wacom volito tablet not
  working (#248832).
- patches.fixes/965-fix: fix detection of aperture size
  versus GTT size on G965 (#258013).
- patches.fixes/sbp2-MODE_SENSE-fix.diff: use proper MODE
  SENSE, fixes recognition of device properties (261086)
- patches.fixes/ipt_CLUSTERIP_refcnt_fix:
  ipv4/netfilter/ipt_CLUSTERIP.c - refcnt fix (238646)
- patches.fixes/reiserfs-fix-vs-13060.diff: reiserfs: fix
  corruption with vs-13060 (257735).
- patches.drivers/ati-rs400_200-480-disable-msi:
  pci-quirks: disable MSI on RS400-200 and RS480 (263893).
- patches.drivers/libata-ahci-ignore-interr-on-SB600:
  ahci.c: walkaround for SB600 SATA internal error issue
  (#264792).

Furthermore, CONFIG_USB_DEVICEFS has been re-enabled to
allow use of USB in legacy applications like VMWare.
(#210899).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-3128");
script_end_attributes();

script_cve_id("CVE-2007-1000", "CVE-2007-1388", "CVE-2007-1592", "CVE-2007-1357");
script_summary(english: "Check for the kernel-3128 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kernel-bigsmp-2.6.18.8-0.3", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.18.8-0.3", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-iseries64-2.6.18.8-0.3", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-ppc64-2.6.18.8-0.3", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.18.8-0.3", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.18.8-0.3", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18.8-0.3", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.18.8-0.3", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-3128-patch-message-2-3128-1", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
