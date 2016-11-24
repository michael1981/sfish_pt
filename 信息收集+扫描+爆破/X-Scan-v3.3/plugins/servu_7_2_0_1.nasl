#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33937);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2008-3731");
  script_bugtraq_id(30739);
  script_xref(name:"OSVDB", value:"47589");
  script_xref(name:"Secunia", value:"31461");

  script_name(english:"Serv-U 7.x < 7.2.0.1 SFTP Directory Creation Logging DoS");
  script_summary(english:"Checks Serv-U version");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Serv-U File Server, an FTP server for
Windows. 

The installed version of Serv-U 7.x is earlier than 7.2.0.1 and thus
reportedly contains an SFTP bug in which directory creation and
logging SFTP commands could lead to an application crash." );
 script_set_attribute(attribute:"see_also", value:"http://www.rhinosoft.com/KnowledgeBase/KBArticle.asp?RefNo=1769" );
 script_set_attribute(attribute:"see_also", value:"http://www.serv-u.com/releasenotes/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Serv-U version 7.2.0.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("global_settings.inc");
include("ftp_func.inc");


port = get_kb_item("Services/ftp");
if (!port) port = 21;

if (!get_port_state(port)) exit(0);


# Make sure the banner looks like Serv-U.
banner = get_ftp_banner(port:port);
if (!banner || " Serv-U FTP Server v" >!< banner) exit(0);


# Identify the version.
#
# nb: the banner doesn't give out granular info; it's good enough if < 7.2,
version = strstr(banner, " Serv-U FTP Server v") - " Serv-U FTP Server v";
version = version - strstr(version, " ready");

if ("7.2" == version)
{
  full_version = "";

  soc = open_sock_tcp(port);
  if (soc)
  {
    s = ftp_recv_line(socket:soc);

    c = "CSID Name=Nessus; Version=1.2.3.4;";
    send(socket:soc, data:string(c, "\r\n"));
    s = ftp_recv_line(socket:soc);

    ftp_close(socket:soc);

    if (strlen(s) && "200 Name=" >< s && "Version=" >< s)
      full_version = ereg_replace(pattern:"^200.+Version=([0-9][0-9.]+).*$", replace:"\1", string:s);
  }

  if (full_version && full_version =~ "^7\.2\.") version = full_version;
  else
  {
    exit(1, "cannot get granular version info");
  }
}


# Check the version.
if (version && version =~ "^7\.([01]($|[^0-9])|2($|\.0\.0))")
{
  if (report_verbosity > 0 )
  {
    report = string(
      "\n",
      "Serv-U version ", version, " appears to be running on the remote host.\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
