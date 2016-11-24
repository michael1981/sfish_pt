#
# This script was written by David Kyger <david_kyger@symantec.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title (3/27/2009)


include("compat.inc");

if(description)
{
  script_id(11872);
  script_version ("$Revision: 1.10 $");

  script_xref(name:"OSVDB", value:"3512");

  script_name(english:"Microsoft IIS ODBC Tool getdrvrs.exe DSN Creation");
 
 script_set_attribute(attribute:"synopsis", value:
"Sensitive data can be read or written on the remote host." );
 script_set_attribute(attribute:"description", value:
"ODBC tools are present on the remote host.

ODBC tools could allow a malicious user to hijack and redirect ODBC traffic, 
obtain SQL user names and passwords or write files to the local drive of a 
vulnerable server.

Example: http://www.example.com/scripts/tools/getdrvrs.exe" );
 script_set_attribute(attribute:"solution", value:
"Remove ODBC tools from the /scripts/tools directory." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 
 summary["english"] = "Checks for the presence of ODBC tools";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 David Kyger");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);



flag = 0;

warning = "The following ODBC tools were found on the server:";




port = get_http_port(default:80);

if(get_port_state(port)) {

   fl[0] = "/scripts/tools/getdrvrs.exe";
   fl[1] = "/scripts/tools/dsnform.exe";
 
   for(i=0;fl[i];i=i+1) 
   { 
    if(is_cgi_installed_ka(item:fl[i], port:port)) 
	{
        warning = warning + string("\n", fl[i]); 
        flag = 1;
        }
   }
    if (flag > 0) {
        security_hole(port:port, extra:warning);
        } else {
          exit(0);
        }
}


