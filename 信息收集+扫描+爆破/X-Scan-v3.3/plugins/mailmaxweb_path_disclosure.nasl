#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11601);
 script_version ("$Revision: 1.10 $");
 script_xref(name:"OSVDB", value:"51865");

 script_name(english:"MailMaxWeb Cookie Application Path Disclosure");
 script_summary(english:"Checks for MailMaxWeb");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The webmail application running on the remote host has an\n",
     "information disclosure vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote server is running MailMaxWeb, a webmail application.\n\n",
     "The version running on the remote host stores the absolute path\n",
     "of this install in the cookie.  A remote attacker could use\n",
     "this information to mount further attacks."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.cirt.dk/advisories/cirt-12-advisory.txt"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"There is no known solution at this time."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

init_cookiejar();

foreach d (cgi_dirs())
{
 if (! isnull(get_http_cookie(name: "IX"))) clear_cookiejar();
 r = http_send_recv3(method: "GET", item:d+"/", port:port);
 if (isnull(r)) exit(0);
 if (get_http_cookie(name: "IX"))
 {
  if (egrep(pattern:".*value=.[A-Za-z]:\\", string: r[1]+r[2]))
  	{
	security_warning(port);
	exit(0);
	}
 }
}
