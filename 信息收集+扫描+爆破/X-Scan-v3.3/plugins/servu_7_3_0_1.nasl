#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34398);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2008-4500", "CVE-2008-4501");
  script_bugtraq_id(31556, 31563);
  script_xref(name:"milw0rm", value:"6660");
  script_xref(name:"milw0rm", value:"6661");
  script_xref(name:"OSVDB", value:"49194");
  script_xref(name:"OSVDB", value:"49195");
  script_xref(name:"OSVDB", value:"54036");
  script_xref(name:"Secunia", value:"32150");

  script_name(english:"Serv-U 7.x < 7.3.0.1 Multiple Remote Vulnerabilities (DoS, Traversal)");
  script_summary(english:"Checks Serv-U version");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by several vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Serv-U File Server, an FTP server for
Windows. 

The installed version of Serv-U 7.x is earlier than 7.3.0.1 and thus
reportedly affected by the following issues :

  - An authenticated remote attacker can cause the service
    to consume all CPU time on the remote host by 
    specifying a Windows port (eg, 'CON:') when using the 
    STOU command provided he has write access to a 
    directory.

  - An authenticated remote attacker can overwrite or create
    arbitrary files via a directory traversal attack in the
    RNTO command.

  - An authenticated remote attacker may be able to upload a
    file to the current Windows directory with rename by 
    placing the destination in '\' (ie, 'My Computer')." );
 script_set_attribute(attribute:"see_also", value:"http://www.rhinosoft.com/KnowledgeBase/KBArticle.asp?RefNo=1769" );
 script_set_attribute(attribute:"see_also", value:"http://www.serv-u.com/releasenotes/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Serv-U version 7.3.0.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C" );
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
# nb: the banner doesn't give out granular info; it's good enough if < 7.3,
version = strstr(banner, " Serv-U FTP Server v") - " Serv-U FTP Server v";
version = version - strstr(version, " ready");

if ("7.3" == version)
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

  if (full_version && full_version =~ "^7\.3\.") version = full_version;
  else
  {
    exit(1, "cannot get granular version info");
  }
}


# Check the version.
if (version && version =~ "^7\.([0-2]($|[^0-9])|3($|\.0\.0))")
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Serv-U version ", version, " appears to be running on the remote host.\n"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
