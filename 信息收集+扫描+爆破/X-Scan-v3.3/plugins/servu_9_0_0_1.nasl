#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(41980);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(36585);
  script_xref(name:"OSVDB", value:"58459");
  script_xref(name:"Secunia", value:"36873");

  script_name(english:"Serv-U < 9.0.0.1");
  script_summary(english:"Checks Serv-U version");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote FTP server is affected by multiple vulnerabilities.\n"
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running Serv-U File Server, an FTP server for\n",
      "Windows.\n",
      "\n",
      "The installed version of Serv-U is earlier than 9.0.0.1 and as such\n",
      "is reportedly affected by following issues :\n",
      "\n",
      "  - Provided 'SITE SET' command is enabled, an authorized \n",
      "    user may be able to crash the remote FTP server by\n",
      "    sending a specially crafted 'SITE SET TRANSFERPROGRESS\n",
      "    ON' command.\n",
      "\n",
      "  - An unprivileged user may be able to view all drives and\n",
      "    virtual paths for drive  '\\'.\n"
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.serv-u.com/releasenotes/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Serv-U version 9.0.0.1 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N"
  );
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/05");

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

version = NULL;
ports = get_kb_list("Services/ftp");
if (isnull(ports)) ports = make_list(21);

foreach port (ports)
{
  if (get_port_state(port))
  {
    # Make sure the banner looks like Serv-U.
    banner = get_ftp_banner(port:port);

    if (banner && " Serv-U FTP Server v" >< banner)
    {
      # Identify the version.
      #
      # nb: the banner doesn't give out granular info; it's good enough if < 9.0.

      version = strstr(banner, " Serv-U FTP Server v") - " Serv-U FTP Server v";
      version = version - strstr(version, " ready");

      if ("9.0" == version)
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
  
        if (full_version && full_version =~ "^9\.0\.") version = full_version;
        else if(full_version) exit(1, "Can't get granular version info.");
      }
      break;
    }
  }
}

# Check the version.
if (version)
{
  if (version =~ "^([0-8]\.|9\.0($|\.0\.0$))")
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Serv-U ", version, " appears to be running on the remote host.\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
  else exit(0, "Serv-U FTP Server "+version+" is running on port "+port+".");
}
else exit(1, "Can't get the Serv-U version.");
