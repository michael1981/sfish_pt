
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-6321
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(33515);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 9 2008-6321: newsx");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-6321 (newsx)");
 script_set_attribute(attribute: "description", value: "Newsx is an NNTP client that will connect to a remote NNTP server and
post outgoing news articles batched by the news system (e.g. INN), as
well as fetch incoming articles.

-
ChangeLog:


Update information :

* Sat Jul 12 2008 Dominik Mierzejewski <rpm greysector net> 1.6-9
- fixed stack buffer overflow in getarticle.c (#454483)
- restored the use of history
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the newsx package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"newsx-1.6-9.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
