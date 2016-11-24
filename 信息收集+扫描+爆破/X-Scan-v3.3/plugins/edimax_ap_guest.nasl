#
# (C) Tenable Network Security, Inc.
#
# Date: 10 Jun 2004 14:26:29 -0000
# From: <msl@velmans-industries.nl>
# To: bugtraq@securityfocus.com
# Subject: Edimax 7205APL
#

include("compat.inc");

if(description)
{
 script_id(12269);
 script_bugtraq_id(10512);
 script_xref(name:"OSVDB", value:"7159");
 script_xref(name:"Secunia", value:"11849");
 script_version("$Revision: 1.5 $");

 script_name(english:"EDIMAX EW-7205APL Wireless AP Default Password Check");
 script_summary(english:"EDIMAX Hidden Password Check");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote access point has an account that uses a default password."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote EDIMAX Access Point ships with a default account\n",
     "('guest'/'1234') which has backup privileges on the remote\n",
     "configuration file.\n\n",
     "If the guest user does a backup of the remote config file, he will be\n",
     "able to obtain the password for the administrator account, since it's\n",
     "saved in cleartext in the config."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:string(
     "Contact the vendor for a fix.  As a temporary workaround,\n",
     "disable the webserver or filter the traffic to this access point\n",
     "webserver via an upstream firewall."
   )
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

# start check

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

r = http_send_recv3(method: "GET", item: "/", port: port, username: "", password: "");
if (isnull(r)) exit(0);
if (r[0] =~ "^HTTP/.* 40[13] ")
{
   r = http_send_recv3(method: "GET", item: "/",  port: port, username: "guest", password: "1234");
   if (isnull(r)) exit(0);
   if (r[0] =~ "^HTTP/.* 200 ")
	{
		security_hole(port);
		exit(0);
	}
}
