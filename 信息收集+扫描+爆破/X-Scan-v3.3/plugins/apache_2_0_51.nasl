#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(14748);
 script_version("$Revision: 1.12 $");

 script_cve_id("CVE-2004-0747", "CVE-2004-0748", "CVE-2004-0751", "CVE-2004-0786", "CVE-2004-0809");
 script_bugtraq_id(11185, 11187);
 script_xref(name:"OSVDB", value:"9523");
 script_xref(name:"OSVDB", value:"9742");
 script_xref(name:"OSVDB", value:"9948");
 script_xref(name:"OSVDB", value:"9991");
 script_xref(name:"OSVDB", value:"9994");
 script_xref(name:"IAVA", value:"2004-t-0032");

 script_name(english:"Apache < 2.0.51 Multiple Vulnerabilities (OF, DoS)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its Server response header, the remote host is running a
version of Apache 2.0 that is older than 2.0.51.  Such versions may be
affected by several issues, including :

  - An input validation issue in apr-util can be triggered
    by malformed IPv6 literal addresses and result in a 
    buffer overflow (CVE-2004-0786).

  - There is a buffer overflow that can be triggered when
    expanding environment variables during configuration
    file parsing (CVE-2004-0747).

  - A segfault in mod_dav_ds when handling an indirect lock
    refresh can lead to a process crash (CVE-2004-0809).

  - A segfault in the SSL input filter can be triggered
    if using 'speculative' mode by, for instance, a proxy
    request to an SSL server (CVE-2004-0751).

  - There is the potential for an infinite loop in mod_ssl
    (CVE-2004-0748)." );
 script_set_attribute(attribute:"see_also", value:"http://issues.apache.org/bugzilla/show_bug.cgi?id=31183" );
 script_set_attribute(attribute:"see_also", value:"http://www.apache.org/dist/httpd/CHANGES_2.0" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache 2.0.51 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "Checks version of Apache";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 443);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("backport.inc");


port = get_http_port(default:80);

banner = get_backport_banner(banner:get_http_banner(port: port));
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/2\.0\.([0-4][0-9]|50)[^0-9]", string:serv))
 {
   security_warning(port);
 }
