
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41558);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  Security update for multipath-tools (multipath-tools-6083)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch multipath-tools-6083");
 script_set_attribute(attribute: "description", value: "Default permissions on the multipathd socket file were to
generous and allowed any user to connect (CVE-2009-0115).

This update also contains the following fixes:
* Error checking in VECTOR_XXX defines (bnc#469269)
* Correct definition of dbg_malloc()
* Double free on path release
* Use noflush for kpartx (bnc#473352)
* multipathd dies immediately after start (bnc#473029)
* Fixup multibus zero-path handling (bnc#476330)
* Use lists for uevent processing (bnc#478874)
* Set stacksize of uevent handling thread (bnc#478874)
* Fix multipathd signal deadlock
* Stack overflow in uev_trigger (bnc#476540)
* Check for NULL argument in vector_foreach_slot
  (bnc#479572)
* Invalid callout formatting for cciss (bnc#419123)
* 'no_partitons' feature doesn't work with aliases
  (bnc#465009)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch multipath-tools-6083");
script_end_attributes();

script_cve_id("CVE-2009-0115");
script_summary(english: "Check for the multipath-tools-6083 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"multipath-tools-0.4.7-34.43", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
