#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(19271);
 script_version ("$Revision: 1.9 $");
 
 name["english"] = "Fedora Core 4 2005-613: fetchmail";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-613 (fetchmail).

Fetchmail is a remote mail retrieval and forwarding utility intended
for use over on-demand TCP/IP links, like SLIP or PPP connections.
Fetchmail supports every remote-mail protocol currently in use on the
Internet (POP2, POP3, RPOP, APOP, KPOP, all IMAPs, ESMTP ETRN, IPv6,
and IPSEC) for retrieval. Then Fetchmail forwards the mail through
SMTP so you can read it through your favorite mail client.

Install fetchmail if you need to retrieve mail over SLIP or PPP
connections.

Update Information:

A buffer overflow was discovered in fetchmail's POP3 client. A malicious
server could cause fetchmail to execute arbitrary code.

The Common Vulnerabilities and Exposures project has assigned the name
CVE-2005-2355 to this issue.

All fetchmail users should upgrade to the updated package, which fixes this iss
ue." );
 script_set_attribute(attribute:"solution", value:
"http://fedoranews.org//mediawiki/index.php/Fedora_Core_4_Update:_fetchmail-6.2.5-7.fc4.1" );
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");



 script_end_attributes();

 
 summary["english"] = "Check for the version of the fetchmail package";
 script_cve_id("CVE-2005-2335");
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
if ( rpm_check( reference:"fetchmail-6.2.5-7.fc4.1", release:"FC4") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"fetchmail-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-2355", value:TRUE);
}
