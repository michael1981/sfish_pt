#
# This script was written by Xue Yong Zhi <xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, desc/solution enhancement, output formatting, OSVDB refs (9/14/09)
# - Updated to use compat.inc, added CVSS score (11/20/2009)



include("compat.inc");

if(description)
{
 script_id(11347);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-1999-0131");
 script_bugtraq_id(717);
 script_xref(name:"OSVDB", value:"1115");
 script_xref(name:"OSVDB", value:"58100");

 script_name(english:"Sendmail < 8.7.6 Multiple Local Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote sendmail server, according to its version number,
has a buffer overflow and denial of service problem. Using
a flaw in the GECOS field handling, it may allow a local
user to gain root access." );
 script_set_attribute(attribute:"solution", value:
"Install Sendmail 8.7.6, 8.8.x or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 script_summary(english:"Checks the version number");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Xue Yong Zhi");
 script_family(english:"SMTP problems");
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
 #looking for Sendmail 8.6.*, 8.7, 8.7.1-8.7.5
 if(egrep(pattern:".*sendmail[^0-9]*(SMI-)?8\.(6|6\.[0-9]+|7|7\.[1-5])/.*", string:banner, icase:TRUE))
 	security_hole(port);
}
