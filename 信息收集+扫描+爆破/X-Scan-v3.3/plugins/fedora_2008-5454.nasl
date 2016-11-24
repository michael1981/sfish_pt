
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-5454
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(33234);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-5454: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-5454 (kernel)");
 script_set_attribute(attribute: "description", value: "The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system: memory allocation, process allocation, device
input and output, etc.

-
Update Information:

Update to kernel 2.6.25.6:
[9]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.25.5
[10]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.25.6    CVE-2008-
1673:
The asn1 implementation in (a) the Linux kernel 2.4 before 2.4.36.6 and 2.6
before 2.6.25.5, as used in the cifs and ip_nat_snmp_basic modules; and (b) the
gxsnmp package; does not properly validate length values during decoding of
ASN.1 BER data, which allows remote attackers to cause a denial of service
(crash) or execute arbitrary code via (1) a length greater than the working
buffer, which can lead to an unspecified overflow; (2) an oid length of zero,
which can lead to an off-by-one error; or (3) an indefinite length for a
primitive encoding.    Bugs fixed:  224005 - pata_pcmcia fails  326411 - Freeze
On Boot w/ Audigy PCMCIA  450332 - F8 - System Lockup after kernel 2.6.25.4-10
450499 - kernel-2.6.25.4-10.fc8 breaks setkey -m tunnel options in ipsec  45050
1
- User Mode Linux (UML) broken on Fedora 9 (and now F8, too)    Additional bugs
fixed:  F9#447518 - Call to capget() overflows buffers  F9#450191 - DMA mode
disabled for DVD drive, reverts to PIO4  F9#439197 - thinkpad x61t crash when
undocking  F9#447812 - Netlink messages from 'tc' to sch_netem module are not
interpreted correctly  F9#449817 - SD card reader causes kernel panic during
startup if card inserted    Additional updates/fixes:  - Fix oops in lirc_i2c
module  - Add lirc support for additional MCE receivers  - Upstream wireless
updates from 2008-05-22    ([11]http://marc.info/?l=linux-
wireless&m=121146112404515&w=2)  - Upstream wireless fixes from 2008-05-28
([12]http://marc.info/?l=linux-wireless&m=121201250110162&w=2)  - Upstream wire
less
fixes from 2008-06-03    ([13]http://marc.info/?l=linux-
wireless&m=121252137324941&w=2)  - Upstream wireless fixes from 2008-06-09
([14]http://marc.info/?l=linux-kernel&m=121304710726632&w=2)  - Upstream wirele
ss
updates from 2008-06-09    ([15]http://marc.info/?l=linux-
netdev&m=121304710526613&w=2)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-5938", "CVE-2008-0600", "CVE-2008-1673");
script_summary(english: "Check for the version of the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kernel-2.6.25.6-27.fc8", prefix:"kernel-", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
