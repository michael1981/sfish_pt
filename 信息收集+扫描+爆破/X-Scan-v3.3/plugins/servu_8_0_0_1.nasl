#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36035);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-0967", "CVE-2009-1031");
  script_bugtraq_id(34125, 34127);
  script_xref(name:"milw0rm", value:"8211");
  script_xref(name:"milw0rm", value:"8212");
  script_xref(name:"OSVDB", value:"52773");
  script_xref(name:"OSVDB", value:"52900");
  script_xref(name:"Secunia", value:"34329");

  script_name(english:"Serv-U < 8.0.0.1 Multiple Vulnerabilities (DoS, Traversal)");
  script_summary(english:"Checks Serv-U version");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote FTP server is affected by multiple vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running Serv-U File Server, an FTP server for\n",
      "Windows.\n",
      "\n",
      "The installed version of Serv-U is earlier than 8.0.0.1 and thus\n",
      "reportedly affected by the following issues :\n",
      "\n",
      "  - A directory traversal vulnerability enables an\n",
      "    authenticated remote attacker to create directories\n",
      "    outside his or her home directory. (CVE-2009-1031)\n",
      "\n",
      "  - An authenticated remote attacker can cause the FTP\n",
      "    service to become saturated for a long period of time\n",
      "    using a long series of 'SMNT' commands without an\n",
      "    argument. During this time, new connections would\n",
      "    not be allowed. (CVE-2009-0967)\n"
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.serv-u.com/releasenotes/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Serv-U version 8.0.0.1 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

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
# nb: the banner doesn't give out granular info; it's good enough if < 8.0.
version = strstr(banner, " Serv-U FTP Server v") - " Serv-U FTP Server v";
version = version - strstr(version, " ready");

if ("8.0" == version)
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

  if (full_version && full_version =~ "^8\.0\.") version = full_version;
  else
  {
    debug_print("can't get granular version info; skipped!");
    exit(1);
  }
}


# Check the version.
if (version && version =~ "^([0-7]\.|8\.0($|\.0\.0$))")
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Serv-U version ", version, " appears to be running on the remote host.\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
