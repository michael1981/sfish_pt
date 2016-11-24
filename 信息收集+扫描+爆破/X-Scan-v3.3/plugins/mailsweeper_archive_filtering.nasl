#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(14360);
 script_cve_id("CVE-2003-0922", "CVE-2003-0929", "CVE-2003-0930");
 script_bugtraq_id(10940);
 script_xref(name:"OSVDB", value:"8844");
 script_xref(name:"Secunia", value:"12301");
 script_version ("$Revision: 1.4 $");

 script_name(english:"MAILsweeper Archive File Filtering Bypass");
 script_summary(english:"Checks the remote banner");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote SMTP server has a security bypass vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running MAILsweeper - a content security solution\n",
     "for SMTP.\n\n",
     "According to its banner, the remote version of MAILsweeper may allow\n",
     "an attacker to bypass the archive filtering settings of the remote\n",
     "server by sending an archive in the format 7ZIP, ACE, ARC, BH, BZIP2,\n",
     "HAP, IMG, PAK, RAR or ZOO."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/ntbugtraq/2003-q1/0141.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to MAILsweeper 4.3.15 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 
 script_dependencie("sendmail_expn.nasl", "smtpserver_detect.nasl");
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
