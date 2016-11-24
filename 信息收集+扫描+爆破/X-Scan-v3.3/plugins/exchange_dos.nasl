#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10558);
 script_version ("$Revision: 1.16 $");
 script_bugtraq_id(1869);
 script_cve_id("CVE-2000-1006");
 script_xref(name:"OSVDB", value:"457");

 script_name(english:"Exchange Malformed MIME Header Handling DoS");
 script_summary(english:"Checks the remote banner");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote SMTP server has a denial of service vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote Exchange server seems to be vulnerable to a flaw that\n",
     "lets malformed MIME headers crash it.\n\n",
     "*** Nessus did not actually test for these flaws - it just relied\n",
     "*** on the banner to identify them. Therefore, this warning may be\n",
     "*** a false positive - especially since the banner DOES NOT CHANGE\n",
     "*** if the patch has been applied."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:"http://www.microsoft.com/technet/security/bulletin/ms00-082.mspx"
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"SMTP problems");
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 
 script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl");
 script_exclude_keys("SMTP/wrapped");
 script_require_ports("Services/smtp", 25);

 exit(0);
}

#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;

if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

if(get_port_state(port))
{
 banner = get_smtp_banner(port:port);
 if(!banner)exit(0);
 if(ereg(string:banner,
	   pattern:".*Microsoft Exchange Internet Mail Service 5\.5\.((1[0-9]{0,3})|(2(([0-5][0-9]{2})|(6(([0-4][0-9])|(50\.(([0-1][0-9])|(2[0-1])))))))).*"))
		security_warning(port);

}
