#
# This script was written by Javier Fernandez-Sanguino <jfs@computer.org>
# 
# This software is distributed under the GPL license, please
# read the license at http://www.gnu.org/licenses/licenses.html#TOCGPL
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref, enhanced description (6/10/09)


include("compat.inc");

if(description)
{
 script_id(11227);
 script_version("$Revision: 1.8 $");
 script_cve_id("CVE-2001-1371");
 script_bugtraq_id(4289);
 script_xref(name:"OSVDB", value:"5407");

 script_name(english:"Oracle 9iAS Default SOAP Configuration Unauthorized Application Deployment");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"In a default installation of Oracle 9iAS v.1.0.2.2, it is possible to
deploy or undeploy SOAP services without the need of any kind of credentials.
This is due to SOAP being enabled by default after installation in order to 
provide a convenient way to use SOAP samples. However, this feature poses a 
threat to HTTP servers with public access since remote attackers can create
soap services and then invoke them remotely. Since SOAP services can
contain arbitrary Java code in Oracle 9iAS this means that an attacker
can execute arbitray code in the remote server." );
 script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technology/deploy/security/pdf/ias_soap_alert.pdf" );
 script_set_attribute(attribute:"see_also", value:"http://www.cert.org/advisories/CA-2002-08.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/476619" );
 script_set_attribute(attribute:"see_also", value:"http://www.nextgenss.com/papers/hpoas.pdf" );
 script_set_attribute(attribute:"solution", value:
"Disable SOAP or the deploy/undeploy feature by editing
$ORACLE_HOME/Apache/Jserver/etc/jserv.conf and removing/commenting
the following four lines:
ApJServGroup group2 1 1 $ORACLE_HOME/Apache/Jserv/etc/jservSoap.properties
ApJServMount /soap/servlet ajpv12://localhost:8200/soap
ApJServMount /dms2 ajpv12://localhost:8200/soap
ApJServGroupMount /soap/servlet balance://group2/soap

Note that the port number might be different from  8200.
Also, you will need to change in the file 
$ORACLE_HOME/soap/werbapps/soap/WEB-INF/config/soapConfig.xml:
<osc:option name='autoDeploy' value='true' />
to
<osc:option name='autoDeploy' value='false' />" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Tests for Oracle9iAS default SOAP installation");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Javier Fernandez-Sanguino");
 script_family(english:"Databases");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache");
 exit(0);
}

# Check starts here

include("http_func.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{ 
# Make a request for /soap/servlet/soaprouter

 req = http_get(item:"/soap/servlet/soaprouter", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("SOAP Server" >< r)	
 	security_hole(port);

 }
}
