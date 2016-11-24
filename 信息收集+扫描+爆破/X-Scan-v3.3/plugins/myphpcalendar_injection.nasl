#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  From: "Frog Man" <leseulfrog@hotmail.com>
#  To: vulnwatch@vulnwatch.org, bugtraq@securityfocus.com
#  Subject: [VulnWatch] myPHPCalendar : Informations Disclosure, File Include


include("compat.inc");

if(description)
{
 script_id(11877);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2006-6812");
 script_xref(name:"OSVDB", value:"35714");
 script_xref(name:"OSVDB", value:"53790");
 script_xref(name:"OSVDB", value:"53791");

 script_name(english:"myPHPcalendar Multiple Scripts cal_dir Parameter Remote File Inclusion");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected
by a remote file include vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote web server appears to be hosting myPHPCalender. The 
installed version contains a vulnerability that could allow an
attacker to make the remote host include php files hosted on a third
party server.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/vulnwatch/2003-q4/0011.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks for the presence of contacts.php");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


function check(url)
{
  local_var res;

  res = http_send_recv3(method:"GET", item:string(url, "/contacts/php?cal_dir=http://xxxxxxxx/"), port:port);
  if (isnull(res)) exit(1, "The remote web server did not respond.");

  if(egrep(pattern:"http://xxxxxxxx/vars\.inc", string:res[2]))
  {
    security_hole(port);
    exit(0);
  }
}

foreach dir (cgi_dirs())
 check(url:dir);
