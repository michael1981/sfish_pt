#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13673);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "Fedora Core 1 2004-060: mailman";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2004-060 (mailman).

Mailman is software to help manage email discussion lists, much like
Majordomo and Smartmail. Unlike most similar products, Mailman gives
each mailing list a webpage, and allows users to subscribe,
unsubscribe, etc. over the Web. Even the list manager can administer
his or her list entirely from the Web. Mailman also integrates most
things people want to do with mailing lists, including archiving, mail
<-> news gateways, and so on.

Documentation can be found in: /usr/share/doc/mailman-2.1.4

When the package has finished installing, you will need to perform some
additional installation steps, these are described in:
/usr/share/doc/mailman-2.1.4/INSTALL.REDHAT

Update Information:

A cross-site scripting (XSS) vulnerability exists in the admin CGI
script for Mailman before 2.1.4.  This update moves Mailman to version
2.1.4 which is not vulnerable to this issue.

Updated packages were made available in February 2004 however the original
update notification email did not make it to fedora-announce-list at
that time." );
 script_set_attribute(attribute:"solution", value:
"http://www.fedoranews.org/updates/FEDORA-2004-060.shtml" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the mailman package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"mailman-2.1.4-1", release:"FC1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mailman-debuginfo-2.1.4-1", release:"FC1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
