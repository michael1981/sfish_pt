#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16111);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2005-0021", "CVE-2005-0022");
 script_bugtraq_id(12185,12188);
 script_xref(name:"OSVDB", value:"12726");
 script_xref(name:"OSVDB", value:"12727");
 script_xref(name:"OSVDB", value:"12946");
 
 script_name(english:"Exim < 4.44 Multiple Overflows");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is vulnerable to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Exim, a message transfer agent (SMTP).

It is reported that Exim is prone to an IPv6 Address and an SPA
authentication buffer overflow.  An attacker, exploiting this issue,
may be able to execute arbitrary code on the remote host. 

Exim must be configured with SPA Authentication or with IPv6 support
to exploit those flaws.

In addition, Exim is vulnerable to two local overflows in command
line option handling. However, Nessus has not tested for these." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Exim 4.44 or newer" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );

 script_end_attributes();

 script_summary(english:"Exim Illegal IPv6 Address and SPA Authentication Buffer Overflow Vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");
 script_dependencie("find_service_3digits.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");
include("global_settings.inc");

#
# RHEL 4, CentOS 4, and more ship wih a (patched) version of exim by default
#
if ( report_paranoia < 2 ) exit(0);

port = get_kb_item("Services/smtp");
if(!port) port = 25;
if (! get_port_state(port)) exit(0);

banner = get_smtp_banner(port:port);
if(!banner)exit(0);
if ( "Exim" >!< banner  ) exit(0);

if(egrep(pattern:"220.*Exim ([0-3]\.|4\.([0-9][^0-9]|[0-3][0-9]|4[0-3][^0-9]))", string:banner))
        security_hole(port);

