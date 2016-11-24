#
# This script was written by Javier Fernandez-Sanguino
# based on sample code written by Renaud Deraison <deraison@cvs.nessus.org>
# in the nessus-plugins mailing list
#
# It is distributed under the GPL license, you can find a copy of this license
# in http://www.gnu.org/copyleft/gpl.html
# 
# Changes by Tenable:
# - Added several additional fingerprints (10/9/2008)
# - Updated plugin title (12/22/08)
# - Changed plugin family (12/22/08)
# - Added Moodle fingerprints (2/12/09)
# - Added N 4.2 fingerprint (9/08/09)

include("compat.inc");

if(description) {
    script_id(20108); 
    script_version ("$Revision: 1.18 $");

    script_xref(name:"OSVDB", value:"39272");

    script_name(english:"Web Server / Application favicon.ico Vendor Fingerprinting");
    script_summary(english:"Attempt to fingerprint web server with favicon.ico");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a graphic image that is prone to
information disclosure." );
 script_set_attribute(attribute:"description", value:
"The 'favicon.ico' file found on the remote web server belongs to a
popular webserver.  This may be used to fingerprint the web server." );
 script_set_attribute(attribute:"solution", value:
"Remove the 'favicon.ico' file or create a custom one for your site." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();


    script_category(ACT_GATHER_INFO);
    script_copyright(english:"This script is Copyright (C) 2005-2009 Javier Fernandez-Sanguino"); 
    script_family(english:"Web Servers");
    script_dependencie("http_version.nasl");
    script_require_ports("Services/www", 80);
    exit(0);
}


# Script code starts here

# Requirements
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);


# Make the request
req = http_get(item:"/favicon.ico", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if ( res == NULL ) exit(0);
md5 = hexstr(MD5(res));


# Known favicons list:
#
# Site specific: Google Web Server and Tenable, should not be seen 
# outside Google, and servers as a way to test the script
server["4987120f4fb1dc454f889e8c92f6dabe"] = "Google Web Server";
server["e298e00b2ff6340343ddf2fc6212010b"] = "Tenable Network Security";

# jericho@attrition contributed to Nikto and Nessus
server["71e30c507ca3fa005e2d1322a5aa8fb2"] = "Apache on Redhat";
server["a28ebcac852795fe30d8e99a23d377c1"] = "SunOne 6.1";
server["41e2c893098b3ed9fc14b821a2e14e73"] = "Netscape 6.0 (AOL)";
server["b25dbe60830705d98ba3aaf0568c456a"] = "Netscape iPlanet 6.0";
server["226ffc5e483b85ec261654fe255e60be"] = "Netscape 4.1";
server["f1876a80546b3986dbb79bad727b0374"] = "NetScreen WebUI";
server["73778a17b0d22ffbb7d6c445a7947b92"] = "Apache on Mac OS X";

# bmartin@tenable additions, 10/08
server["799f70b71314a7508326d1d2f68f7519"] = "JBoss Server";
server["4644f2d45601037b8423d45e13194c93"] = "Apache Tomcat";
server["31aa07fe236ee504c890a61d1f7f0a97"] = "Apache 2.2.4 (docs/manual/images/favicon.ico)";
server["bd0f7466d35e8ba6cedd9c27110c5c41"] = "Serena Collage 4.6 (servlet/images/collage_app.ico)";
server["7cc1a052c86cc3d487957f7092a6d8c3"] = "Horde IMP 3.1.4 (also used in Horde Groupware Webmail 1.0.1)";
server["f567fd4927f9693a7a2d6cacf21b51b6"] = "Horde IMP 4.1.4 (also used in Horde Groupware Webmail 1.0.1)";
server["81df3601d6dc13cbc6bd8212ef50dd29"] = "Horde Groupware Webmail 1.0.1 (Nag Theme)";
server["919e132a62ea07fce13881470ba70293"] = "Horde Groupware Webmail 1.0.1 (Ingo Theme)";
server["f5f2df7eec0d1c3c10b58960f3f8fb26"] = "Horde Groupware Webmail 1.0.1 (Mnemo Theme)";
server["ff260e80f5f9ca4b779fbd34087f13cf"] = "Horde Groupware Webmail 1.0.1 (Turba Theme)";
server["a5b126cdeaa3081f77a22b3e43730942"] = "Horde Groupware Webmail 1.0.1 (Kronolith Theme)";
server["dc0816f371699823e1e03e0078622d75"] = "Aruba Network Devices (HTTP(S) login page)";
server["d41d8cd98f00b204e9800998ecf8427e"] = "Joomla! CMS (Unknown version)";
server["73778a17b0d22ffbb7d6c445a7947b92"] = "Apache HTTP Server on Apple Mac OS X Server";
server["f097f0adf2b9e95a972d21e5e5ab746d"] = "Citrix Access Server";
server["28893699241094742c3c2d4196cd1acb"] = "Xerox DocuShare";
server["80656aabfafe0f3559f71bb0524c4bb3"] = "Macromedia Breeze";
server["f6e9339e652b8655d4e26f3e947cf212"] = "eGroupWare 1.0.0.009 (/phpgwapi/templates/idots/images/favicon.ico)";
server["48c02490ba335a159b99343b00decd87"] = "Octeth Technologies oemPro 3.5.5.1";

# bmartin@tenable additions, 2/09
server["933a83c6e9e47bd1e38424f3789d121d"] = "Moodle 1.9.x (multiple default themes)";
server["b6652d5d71f6f04a88a8443a8821510f"] = "Moodle 1.9.x (Cornflower Theme, /theme/cornflower/favicon.ico)";

# bmartin@tenable addition, 6/09
server["eb6d4ce00ec36af7d439ebd4e5a395d7"] = "Mailman";

# bmartin@tenable addition, 9/09
server["e298e00b2ff6340343ddf2fc6212010b"] = "Nessus 4.x Web Client";

# bmartin@tenable addition, 10/09
server["31aa07fe236ee504c890a61d1f7f0a97"] = "Apache Software Foundation Project";
server["04d89d5b7a290334f5ce37c7e8b6a349"] = "Atlassian Jira Bug Tracker";
server["ebe293e1746858d2548bca99c43e4969"] = "Mantis Bug Tracker, /bugs/images/favicon.ico)";

# pdavis@tenable addition, 10/09
server["d80e364c0d3138c7ecd75bf9896f2cad"] = "Apache Tomcat 6.0.18";
server["a6b55b93bc01a6df076483b69039ba9c"] = "Fogbugz 6.1.44";

# Check the hash against what we know about.
if (server[md5]) {
  if (report_verbosity > 0) {
    report = string(
      "\n",
      "The 'favico.ico' fingerprints this webserver as ", server[md5], ".\n"
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);

  exit(0);
}


# This is a sample script to obtain the list of favicon files from a Webscarab
# directory. Can be useful to add new favicon after a pen-test:
# 
##!/bin/sh
#
#pwd=`pwd`
#find . -name "*response*" |
#while read file ; do
#	if grep -q "^Content-type: image/x-icon" $pwd/$file; then
#	# It's an ico file
#
#	server=`grep --binary-files=text "^Server" $pwd/$file`
#	size=`stat -c %B $pwd/$file`
#		if [ ! -n "$server" ] 
#		then
#			server=`echo $server | sed -e 's/Server: //'`
#		else
#			server="unknown"
#		fi
#	echo "$server,$file,$size"
#	fi
#done

