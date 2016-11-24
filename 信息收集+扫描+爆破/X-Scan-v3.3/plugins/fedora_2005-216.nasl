#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(18314);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2005-0398");
 
 name["english"] = "Fedora Core 2 2005-216: ipsec-tools";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-216 (ipsec-tools).

This is the IPsec-Tools package. You need this package in order to
really use the IPsec functionality in the linux-2.5+ kernels. This
package builds:

- setkey, a program to directly manipulate policies and SAs
- racoon, an IKEv1 keying daemon

Update Information:

This update fixes a potential DoS in parsing ISAKMP headers in racoon.
(CVE-2005-0398)" );
 script_set_attribute(attribute:"solution", value:
"http://www.fedoranews.org/blog/index.php?p=478" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the ipsec-tools package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"ipsec-tools-0.5-2.fc2", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ipsec-tools-debuginfo-0.5-2.fc2", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"ipsec-tools-", release:"FC2") )
{
 set_kb_item(name:"CVE-2005-0398", value:TRUE);
}
