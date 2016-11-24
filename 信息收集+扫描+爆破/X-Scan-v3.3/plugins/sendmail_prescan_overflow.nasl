#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  Date: Wed, 17 Sep 2003 11:19:46 +0200 (CEST)
#  From: Michal Zalewski <lcamtuf@dione.ids.pl>
#  To: bugtraq@securityfocus.com, <vulnwatch@securityfocus.com>,
#      <full-disclosure@netsys.com>
#	Subject: Sendmail 8.12.9 prescan bug (a new one) [CVE-2003-0694]


include("compat.inc");


if(description)
{
 script_id(11838);
 script_version("$Revision: 1.17 $");

 script_cve_id("CVE-2003-0681", "CVE-2003-0694");
 script_bugtraq_id(8641, 8649);
 script_xref(name:"IAVA", value:"2003-b-0005");
 script_xref(name:"OSVDB", value:"2577");
 script_xref(name:"RHSA", value:"RHSA-2003:283-01");
 script_xref(name:"SuSE", value:"SUSE-SA:2003:040");

 script_name(english:"Sendmail < 8.12.10 prescan() Function Remote Overflow");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"The remote mail server is prone to multiple buffer overflow attacks."
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "According to its version number, the remote sendmail server is\n",
   "between 5.79 to 8.12.9.  Such versions are reportedly vulnerable to\n",
   "remote buffer overflow attacks, one in the 'prescan()' function and\n",
   "another involving its ruleset processing.  A remote user may be able\n",
   "to leverage these issues to gain root privileges."
  )
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://archives.neohapsis.com/archives/fulldisclosure/2003-q3/4119.html"
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://www.kb.cert.org/vuls/id/108964"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Sendmail version 8.12.10 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();
 
 script_summary(english:"Checks the version number"); 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");
 if ( ! defined_func("bn_random") )
	script_dependencie("smtpserver_detect.nasl");
 else
 	script_dependencie("smtpserver_detect.nasl", "solaris7_107684.nasl", "solaris7_x86_107685.nasl", "solaris8_110615.nasl", "solaris8_x86_110616.nasl", "solaris9_113575.nasl", "solaris9_x86_114137.nasl");
 script_require_ports("Services/smtp", 25);
 script_require_keys("SMTP/sendmail");
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");
include("backport.inc");

if ( get_kb_item("BID-8641") ) exit(0);

port = get_kb_item("Services/smtp");
if(!port) port = 25;

banner = get_smtp_banner(port:port);
if(banner)
{
 banner = get_backport_banner(banner:banner);
 if(egrep(pattern:"Sendmail.*(Switch\-((1\.)|(2\.(0\.|1\.[0-4])))|(/|UCB| )([5-7]\.|[^/]8\.([0-9](\.|;|$)|10|11\.[0-6][^0-9]|12\.[0-9](\/| |\.|\+)))).*", string:banner, icase:TRUE))
    security_hole(port);
 else if(egrep(pattern:"Sendmail (5\.79.*|5\.[89].*|[67]\..*|8\.[0-9]\..*|8\.10\..*|8\.11\.[0-6]|8\.12\.[0-9]|SMI-[0-8]\.([0-9]|1[0-2]))/.*",
  string:banner, icase:TRUE))
    security_hole(port);
}
