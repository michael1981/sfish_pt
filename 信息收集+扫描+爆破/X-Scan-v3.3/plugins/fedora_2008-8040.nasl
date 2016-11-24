
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-8040
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34203);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-8040: ssmtp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-8040 (ssmtp)");
 script_set_attribute(attribute: "description", value: "A secure, effective and simple way of getting mail off a system to your mail
hub. It contains no suid-binaries or other dangerous things - no mail spool
to poke around in, and no daemons running in the background. Mail is simply
forwarded to the configured mailhost. Extremely easy configuration.

WARNING: the above is all it does; it does not receive mail, expand aliases
or manage a queue. That belongs on a mail hub with a system administrator.

-
Update Information:

Fix for CVE-2008-3962
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-3962");
script_summary(english: "Check for the version of the ssmtp package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"ssmtp-2.61-11.6.fc8.1", release:"FC8") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
