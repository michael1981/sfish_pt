#
# (C) Tenable Network Security, Inc.
#

# Note that we need to be authenticated for this check
# to work properly.
#


include("compat.inc");

if(description)
{
 script_id(11663);
 script_version("$Revision: 1.15 $");
 script_cve_id("CVE-2003-0317");
 script_bugtraq_id(7661);
 script_xref(name:"OSVDB", value:"3183");
 script_xref(name:"Secunia", value:"8850");

 script_name(english:"iisPROTECT Encoded URL Authentication Bypass");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by an
authentication bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running iisprotect, an IIS add-on to 
protect the pages served by this server.

There is a bug in the remote version of iisprotect which may allow
an attacker to bypass protection by hex-encoding the requested URLs." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/vulnwatch/2003-q2/0080.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to iisprotect 2.2.0.9 or later as this reportedly fixes the
issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Determines if iisprotect can be escaped");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

function encode(dir)
{
 local_var enc, i;
 for(i=strlen(dir) - 2;i>1;i--)
 {
  if(dir[i] == "/")break;
 }
 if(i <= 1)return NULL;
 
 enc = "%" + hex(ord(dir[i+1])) - "0x";
 dir = insstr(dir, enc, i+1, i+1);
 return dir;
}
function check(loc)
{
 local_var w, res;
 w = http_send_recv3(method:"GET", item:loc, port:port);
 if (isnull(w)) exit(1, "the web server did not answer");
 res = w[0];
 if (ereg(pattern:"HTTP/[0-9]\.[0-9] (40[13]|30[0-9]) ", string:res))return 300;
 else if(ereg(pattern:"HTTP/[0-9]\.[0-9] 200 ", string:res))return 200;
 else return -1;
}


dirs = get_kb_list(string("www/", port, "/content/auth_required"));
if(!isnull(dirs))dirs = make_list(dirs, "/iisprotect/sample/protected");
else dirs = make_list("/iisprotect/sample/protected");

if(get_port_state(port))
{
 foreach dir (dirs)
 {
  if( check(loc:dir) == 300 )
  {
   origdir = dir;
   dir = encode(dir:dir);
   if( dir && check(loc:dir) == 200 )
   {
report = "
The url :

	" + origdir + " 

is protected (code 30x) but the URL :

	" + dir + "

is does not ask for a password (code 200).";
    security_hole(port:port, extra:report);
    exit(0);
    }
  }
 }
}
