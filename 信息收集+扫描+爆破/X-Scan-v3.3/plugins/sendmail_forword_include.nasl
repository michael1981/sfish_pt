#
# This script was written by Xue Yong Zhi <xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, OSVDB ref, output formatting (9/14/09)

if(description)
{
 script_id(11349);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-1999-0129");
 script_bugtraq_id(715);
 script_xref(name:"OSVDB", value:"1113");

 script_name(english:"Sendmail < 8.8.4 Group Write File Hardlink Privilege Escalation");

 desc["english"] = "
The remote sendmail server, according to its version number,
allows local users to write to a file and gain group permissions
via a .forward or :include: file.

Solution : 

Install sendmail newer than 8.8.4 or install a vendor
supplied patch.

Risk factor : 

High (Local) / None (remote with no account)";

 script_description(english:desc["english"]);
 script_summary(english:"Checks the version number");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Xue Yong Zhi");
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
 #looking for Sendmail 8.8, 8.8.1-8.8.3
 if(egrep(pattern:".*sendmail[^0-9]*8\.(8|8\.[1-3])/.*", string:banner, icase:TRUE))
 	security_hole(port);
}
