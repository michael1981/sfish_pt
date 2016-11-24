#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPL v2
#

# Changes by Tenable:
# - "Services/www" check
# - Family changed to "Service detection"
# - Request fixed
# - title touch-up (9/10/09)


include("compat.inc");

if(description)
{
 script_id(20377);
 script_version("$Revision: 1.4 $");
 
 script_name(english:"Windows Server Update Services (WSUS) Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host appears to be running Windows Server Update Services." );
 script_set_attribute(attribute:"description", value:
"This product is used to deploy easily and quickly latest Microsoft
product updates." );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/windowsserversystem/updateservices/default.mspx" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );

script_end_attributes();

 script_summary(english:"Checks for WSUS console");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2009 David Maciejak");
 script_family(english:"Service detection");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80, 8530);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

ports = get_kb_list ("Services/www");

if (isnull(ports))
  ports = make_list (8530);
else
  ports = make_list (8530, ports);


foreach port (ports)
{
 if(get_port_state(port))
 {
  req = http_get(item:"/Wsusadmin/Errors/BrowserSettings.aspx", port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if( r == NULL )exit(0);

  if ( egrep (pattern:'<title>Windows Server Update Services error</title>.*href="/WsusAdmin/Common/Common.css"', string:r) ||
       egrep (pattern:'<div class="CurrentNavigation">Windows Server Update Services error</div>', string:r) )
  {
   security_note(port);
  }
 }
}

