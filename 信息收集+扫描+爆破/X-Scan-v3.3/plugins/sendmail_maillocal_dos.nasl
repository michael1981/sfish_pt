#
# This script was written by Xue Yong Zhi <xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, OSVDB ref, output formatting (9/14/09)
# - Updated to use compat.inc, added CVSS score (11/20/2009)



include("compat.inc");

if(description)
{
 script_id(11351);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2000-0319");
 script_bugtraq_id(1146);
 script_xref(name:"OSVDB", value:"1299");

 script_name(english:"Sendmail < 8.10.0 mail.local Newline Handling Remote DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a
denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"mail.local in the remote sendmail server, according to its 
version number, does not properly identify the .\n string 
which identifies the end of message text, which allows a 
remote attacker to cause a denial of service or corrupt 
mailboxes via a message line that is 2047 characters 
long and ends in .\n." );
 script_set_attribute(attribute:"solution", value:
"Install sendmail version 8.10.0 and higher, or install 
a vendor supplied patch." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );


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
 #looking for Sendmail 5.58,5,59, 8.6.*, 8.7.*, 8.8.*, 8.9.1, 8.9.3(icat.nist.gov)
 #bugtrap id 1146 only said 8.9.3, I guess it want to say 8.9.3 and older
 if(egrep(pattern:".*sendmail[^0-9]*(5\.5[89]|8\.([6-8]|[6-8]\.[0-9]+)|8\.9\.[1-3]|SMI-[0-8]\.)/.*", string:banner, icase:TRUE))
 	security_warning(port);
}
