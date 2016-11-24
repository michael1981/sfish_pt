#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40354);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-1999-0508");

  script_name(english:"OpenWrt Router with a Blank Password (telnet check)");
  script_summary(english:"Tries to access OpenWrt without a password");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote router does not have a password set."
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running OpenWrt, an open source Linux distribution\n",
      "for embedded devices, especially routers. \n",
      "\n",
      "It is currently configured without a password, which is the case by\n",
      "default.  Anyone can connect to the device via Telnet and gain\n",
      "administrative access to it."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://oldwiki.openwrt.org/OpenWrtDocs%282f%29Using.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Set a password for the device."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/07/23"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/telnet", 23);

  exit(0);
}


include("global_settings.inc");
include("telnet_func.inc");


port = get_kb_item("Services/telnet");
if (!port) port = 23;
if (!get_tcp_port_state(port)) exit(0, "No Telnet service was detected.");


banner = get_telnet_banner(port:port);
if (
  banner &&
  "Use 'passwd' to set your login password" >< banner &&
  "W I R E L E S S   F R E E D O M" >< banner &&
  "root@" >< banner
)
{
  # Unless we're paranoid, make sure it's really OpenWrt.
  if (report_paranoia < 2)
  {
    soc = open_sock_tcp(port);
    if (soc)
    {
      res = telnet_negotiate(socket:soc);
      res += recv_until(socket:soc, pattern:"root@");
      if (!res)
      {
        close(soc);
        exit(0, "Didn't receive a command prompt.");
      }
      send(socket:soc, data:'cat /proc/version\r\n');

      res = recv_until(socket:soc, pattern:"OpenWrt");
      if (!res)
      {
        close(soc);
        exit(0, "'/proc/version' doesn't mention OpenWrt.");
      }
      close(soc);
    }
    else exit(1, "Can't open a socket to verify it's really OpenWrt.");
  }

  set_kb_item(name:"openwrt/blank_telnet_password", value:TRUE);

  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "The remote device uses the following banner :\n",
      "\n",
      crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
      banner, "\n",
      crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
exit(0, "The host is not affected.");
