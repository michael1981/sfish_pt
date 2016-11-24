# This script was created by Jason Lidow <jason@brandx.net>
# The vulnerability was originally discovered by ts@securityoffice.net 

include("compat.inc");

if(description)
{
        script_id(11151);
        script_bugtraq_id(5803);
	script_cve_id("CVE-2002-1521");
	script_xref(name:"OSVDB", value:"5371");
        script_version("$Revision: 1.11 $");
        script_name(english:"Webserver 4D Cleartext Password Storage");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server is affected by an information disclosure
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its Server response header, the remote web server is
Webserver 4D 3.6 or lower.  Such versions store all usernames and
passwords in cleartext in the file 'Ws4d.4DD' in the application's
installation directory.  A local attacker may use this flaw to gain
unauthorized privileges on this host."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/vulnwatch/2002-q3/0128.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Contact the vendor for an update."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N"
  );
  script_end_attributes();
        script_summary(english:"Checks for Webserver 4D");

        script_category(ACT_GATHER_INFO);

        script_copyright(english:"This script is Copyright (C) 2002-2009 Jason Lidow <jason@brandx.net>");
        script_family(english:"CGI abuses");
        script_dependencie("http_version.nasl", "find_service1.nasl", "httpver.nasl", "no404.nasl");
        script_require_ports("Services/www", 80);
        exit(0);
}


include("http_func.inc");
port = get_http_port(default:80);


banner = get_http_banner(port:port);


poprocks = egrep(pattern:"^Server.*", string: banner);
if(banner)
{
        if("Web_Server_4D" >< banner) 
	{
                yo = string("\nThe following banner was received : ", poprocks, "\n");

                security_note(port:port, extra:yo);
 	}
}
