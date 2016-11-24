#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(19735);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2005-2871");
 
 name["english"] = "Fedora Core 4 2005-873: mozilla";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-873 (mozilla).

Mozilla is an open-source Web browser, designed for standards
compliance, performance, and portability.

Update Information:

An updated mozilla package that fixes a security bug is now
available for Fedora Core 4.

This update has been rated as having critical security
impact by the Fedora Security Response Team.

Mozilla is an open source Web browser, advanced email and
newsgroup client, IRC chat client, and HTML editor.

A bug was found in the way Mozilla processes certain
international domain names. An attacker could create a
specially crafted HTML file, which when viewed by the victim
would cause Mozilla to crash or possibly execute arbitrary
code. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-2871 to this
issue.

Users of Mozilla are advised to upgrade to this updated
package that contains a backported patch and is not
vulnerable to this issue." );
 script_set_attribute(attribute:"solution", value:
"Get the newest Fedora Updates" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the mozilla package";
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
if ( rpm_check( reference:"mozilla-1.7.10-1.5.2", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.7.10-1.5.2", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.7.10-1.5.2", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.7.10-1.5.2", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.7.10-1.5.2", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.10-1.5.2", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.10-1.5.2", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.7.10-1.5.2", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"mozilla-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-2871", value:TRUE);
}
