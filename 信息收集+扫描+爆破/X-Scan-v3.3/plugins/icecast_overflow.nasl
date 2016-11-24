#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10600);
 script_bugtraq_id(2264);
 script_cve_id("CVE-2001-0197");
 script_xref(name:"OSVDB", value:"496");
 script_version ("$Revision: 1.14 $");
 
 script_name(english:"Icecast utils.c fd_write Function Format String");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is vulnerable to a remote code execution attack." );
 script_set_attribute(attribute:"description", value:
"The remote server claims to be running Icecast 1.3.7 or 1.3.8beta2.

These versions are vulnerable to a format string attack which may
allow an attacker to execute arbitary commands on this host." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Jan/0323.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Icecast format string";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl");
  script_require_ports("Services/www", 8000);
 exit(0);
}

#
# The script code starts here
#

include("http.inc");
include("misc_func.inc");
include("global_settings.inc");

port = get_http_port(default:8000);
if(!port) exit(0);

banner = tolower(get_http_banner(port:port));
if ( ! banner ) exit(0);

if("icecast/" >< banner && egrep(pattern:"icecast/1\.3\.(7|8 *beta[012])", string:banner))
      security_hole(port);
