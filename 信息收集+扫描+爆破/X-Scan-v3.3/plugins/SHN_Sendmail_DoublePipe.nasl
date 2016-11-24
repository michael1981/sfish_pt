#
# This script was written by Vincent Renardias <vincent@strongholdnet.com>
#
# Licence: GPLv2
#
# Changes by Tenable:
# - Revised description (1/22/2009)
# - Updated to use compat.inc, added CVSS score (11/20/2009)


include("compat.inc");

if(description)
{
 script_id(11321);
 script_bugtraq_id(5845);
 script_cve_id("CVE-2002-1165", "CVE-2002-1337");
 script_xref(name:"OSVDB", value:"4502");
 script_xref(name:"OSVDB", value:"9305");
 script_xref(name:"RHSA", value:"RHSA-2003:073-06");
 script_xref(name:"SuSE", value:"SUSE-SA:2003:023");
 script_version ("$Revision: 1.15 $");

 script_name(english:"Sendmail 8.8.8 - 8.12.7 Multiple Vulnerabilities (Bypass, OF)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"smrsh (supplied by Sendmail) is designed to prevent the execution of
commands outside of the restricted environment. However, when commands
are entered using either double pipes (||) or a mixture of dot
and slash characters, a user may be able to bypass the checks
performed by smrsh. This can lead to the execution of commands
outside of the restricted environment.

In addition, a function in headers.c does not properly sanitize input
supplied via the 'Address Field' causing an exploitable buffer overflow
condition. However, Nessus has not checked for this." );
 script_set_attribute(attribute:"solution", value:
"upgrade to the latest version of Sendmail (or at least 8.12.8)." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Checks sendmail's version number"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 StrongHoldNet");
 
 family["english"] = "SMTP problems";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 script_require_keys("SMTP/sendmail");
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;

banner = get_smtp_banner(port:port);

if(banner)
{
 if(egrep(pattern:"Sendmail.*[^/](8\.8\.[89]|8\.9\..*|8\.1[01]\..*|8\.12\.[0-7][^0-9])/", string:banner))
        security_hole(port);
}

