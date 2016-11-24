#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11805);
 script_version("$Revision: 1.13 $");
 script_bugtraq_id(8273);
 script_xref(name:"OSVDB", value:"3856");

 script_name(english:"e107 db.php User Database Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that suffers from an
information disclosure flaw." );
 script_set_attribute(attribute:"description", value:
"There is a flaw in the remote installation of e107 - the script
'admin/db.php' lets anyone obtain a dump of the remote SQL database by
sending the proper request to the remote server.  An attacker may use
this flaw to obtain the MD5 hashes of the passwords of the users of
this web site." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/330332" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2003-07/0336.html" );
 script_set_attribute(attribute:"solution", value:
"The vendor claims the db_dump code requires admin credentials,
although Nessus was able to exploit the issue without them." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );


script_end_attributes();

 script_summary(english:"e107 flaw");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencies("e107_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


data = "dump_sql=foo";


# Test an install.
install = get_kb_item(string("www/", port, "/e107"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  if ( is_cgi_installed3(item:dir + "/admin/db.php", port:port) ) {
    host = get_host_name();
    r = http_send_recv3(method:"POST ", item: strcat(dir, "/admin/db.php"), version: 11, port: port,
      add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
      data: data);
    if (isnull(r)) exit(0);
    buf = r[2];

    if ("e107 sql-dump" >< buf) {
      if (report_verbosity > 0) {
        db = strstr(buf, '\r\n\r\n');
        if (db) db = substr(db, 0, 255);
        else db = buf;

        report = string(
          "Here is an extract of the dump of the remote database.\n",
          "\n",
          db
        );
      }
      else report = NULL;

      security_warning(port:port, extra:report);
      exit(0);
    }
  }
}
