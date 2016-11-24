#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11650);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2003-1477");
 script_bugtraq_id(10937, 7562);
 script_xref(name:"OSVDB", value:"8656");
 script_xref(name:"Secunia", value:"12277");

 script_name(english:"MAILsweeper for SMTP PowerPoint Document Processing DoS");
 script_summary(english:"Checks the remote banner");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote SMTP server has a denial of service vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running MAILsweeper - a content security solution\n",
     "for SMTP.\n\n",
     "According to its banner, the remote version of MAILsweeper consumes\n",
     "all available CPU resources when processing a malformed PowerPoint\n",
     "file, causing the server to become non-responsive.  A remote attacker\n",
     "could exploit this to cause a denial of service."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?70470982 (vendor patch)"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to MAILsweeper 4.3.15 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"SMTP problems");

 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");

 script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl");
 script_exclude_keys("SMTP/wrapped");
 script_require_ports("Services/smtp", 25);
 exit(0);
}


include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

banner = get_smtp_banner(port:port);
if ( ! banner ) exit(0);
if(egrep(string:banner, pattern:"^220 .* MAILsweeper ESMTP Receiver Version ([0-3]\.|4\.([0-2]\.|3\.([0-9]|1[0-4])[^0-9])).*$")) security_hole(port);
