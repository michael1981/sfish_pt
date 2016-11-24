#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  Date: Tue, 13 May 2003 17:26:39 -0500
#  From: cdowns <cdowns@drippingdead.com>
#  To: webappsec@securityfocus.com, pen-test@securityfocus.com
#  Subject: Owl Intranet Engine - bypass admin 



include("compat.inc");

if (description)
{
 script_id(11626);
 script_version ("$Revision: 1.10 $");
 script_xref(name:"OSVDB", value:"52976");

 script_name(english:"Owl browse.php Authentication Bypass");
 script_set_attribute(attribute:"synopsis", value:
"The remote host has a PHP script that is affected by an
authentication bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is using owl intranet engine, an open-source
file sharing utility written in php. There is a flaw in this 
application which may allow an attacker to browse files on 
this host without having to log in." );
 script_set_attribute(attribute:"solution", value:
"None at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Determines owl is installed");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");



port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if(!can_host_php(port:port)) exit(0);


dir = list_uniq(make_list("/filemgr", cgi_dirs(),  "/intranet"));
		


foreach d (dir)
{
 req = http_get(item:d + "/browse.php", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( isnull(res) ) exit(0);
 if("User: <A HREF='prefs.php?owluser=2&sess=0&parent=1&expand=1&order=name&sortname=ASC'>Anonymous</A> " >< res )
 {
  req = http_get(item:d + "/browse.php?loginname=nessus&parent=1&expand=1&order=creatorid&sortposted=ASC", port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if( isnull(res) ) exit(0);
  if("User: <A HREF='prefs.php?owluser=&sess=0&parent=1&expand=1&order=creatorid&sortname=ASC'>Owl</A>" >< res)
  	{
	security_warning(port);
	exit(0);
	}
 }
}
