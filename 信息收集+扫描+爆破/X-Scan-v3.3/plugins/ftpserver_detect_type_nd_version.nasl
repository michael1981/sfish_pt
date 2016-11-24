#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(10092);
 script_version ("$Revision: 1.36 $");
 name["english"] = "FTP Server Detection";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"An FTP server is listening on this port." );
 script_set_attribute(attribute:"description", value:
"It is possible to obtain the banner of the remote FTP server by
connecting to the remote port." );
 script_set_attribute(attribute:"solution", value:
"N/A" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_end_attributes();
 
 summary["english"] = "Connects to port 21";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Service detection";
 script_family(english:family["english"]);
 script_require_ports("Services/ftp", 21);
 script_dependencies("find_service_3digits.nasl", "doublecheck_std_services.nasl", "ftpd_no_cmd.nasl", "ftpd_any_cmd.nasl", "ftpd_bad_sequence.nasl", "fake_3digits.nasl", "ftp_kibuv_worm.nasl");
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if (!port) port = 21;

banner = get_ftp_banner(port: port);

if(
  banner &&
  (
    "421 Service not available" >!< banner ||
    "421 Too many connections" >!< banner ||
    "530 Connection refused" >!< banner
  )
)
{
 if ("NcFTPd" >< banner) set_kb_item(name:"ftp/ncftpd", value:TRUE);
 if (" ProFTPD " >< banner || "-ProFTPD " >< banner || "(ProFTPD" >< banner) set_kb_item(name:"ftp/proftpd", value:TRUE);
 if(egrep(pattern:".*icrosoft FTP.*",string:banner))set_kb_item(name:"ftp/msftpd", value:TRUE);
 if(egrep(pattern:".*heck Point Firewall-1 Secure FTP.*", string:banner))set_kb_item(name:"ftp/fw1ftpd", value:TRUE);
 if(egrep(pattern:".*Version wu-.*", string:banner))set_kb_item(name:"ftp/wuftpd", value:TRUE);
 if(egrep(pattern:".*xWorks.*", string:banner))set_kb_item(name:"ftp/vxftpd", value:TRUE);

 if ("ProFTPD" >< banner && "500 GET not understood" >< banner)
  banner = banner - strstr(banner, "500 GET not understood");

 report = '\nThe remote FTP banner is :\n\n' + banner;
 security_note(port:port, extra:report);
}
