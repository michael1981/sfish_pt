#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(19720);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2005-2496");
 
 name["english"] = "Fedora Core 3 2005-812: ntp";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-812 (ntp).

The Network Time Protocol (NTP) is used to synchronize a computer's
time with another reference time source. The ntp package contains
utilities and daemons that will synchronize your computer's time to
Coordinated Universal Time (UTC) via the NTP protocol and NTP servers.
The ntp package includes ntpdate (a program for retrieving the date
and time from remote machines via a network) and ntpd (a daemon which
continuously adjusts system time).

Install the ntp package if you need tools for keeping your system's
time synchronized via the NTP protocol.

Update Information:

When starting xntpd with the -u option and specifying the
group by using a string not a numeric gid the daemon uses
the gid of the user not the group. This problem is now fixed
by this update.

The Common Vulnerabilities and Exposures project assigned
the name CVE-2005-2496 to this issue." );
 script_set_attribute(attribute:"solution", value:
"Get the newest Fedora Updates" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the ntp package";
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
if ( rpm_check( reference:"ntp-4.2.0.a.20040617-5.FC3", release:"FC3") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"ntp-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-2496", value:TRUE);
}
