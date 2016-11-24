#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25037);
  script_version("$Revision: 1.7 $");

  script_name(english: "Printer Job Language (PJL) Detection");
  script_summary(english: "Talks PJL to HP JetDirect service"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote service uses the PJL (Printer Job Language) protocol." );
 script_set_attribute(attribute:"description", value:
"The remote service answered to a HP PJL request. 

This is indicates the remote device is probably a printer running
JetDirect. 

Through PJL, users can submit printing jobs, transfer files to or from
the printers, change some settings, etc..." );
 script_set_attribute(attribute:"see_also", value:"http://www.maths.usyd.edu.au/u/psz/ps.html" );
 script_set_attribute(attribute:"see_also", value:"http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=bpl04568" );
 script_set_attribute(attribute:"see_also", value:"http://h20000.www2.hp.com/bc/docs/support/SupportManual/bpl13208/bpl13208.pdf" );
 script_set_attribute(attribute:"see_also", value:"http://h20000.www2.hp.com/bc/docs/support/SupportManual/bpl13207/bpl13207.pdf" );
 script_set_attribute(attribute:"risk_factor", value: "None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english: "Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports(9100, "Services/unknown");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");

if (thorough_tests)
{
 ports = get_kb_item("Service/unknown");
 ports = add_port_in_list(list: ports, port: 9100);
}
else
 ports = make_list(9100);

foreach port (ports)
 if ( get_port_state(port) && 
      service_is_unknown(port: port) &&
      # No banner for PJL, as far as I know
      strlen(get_unknown_banner(port: port, dontfetch: 1)) == 0 )
 {
  s = open_sock_tcp(port);
  if (s)
  {
   send(socket: s, data: '\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X\r\n');
   r = recv(socket: s, length: 1024);
   if (! isnull(r) && '@PJL INFO ID\r\n' >< r )
   {
    lines = split(r, keep: 0);
    if (max_index(lines) >= 1 && strlen(lines[1]) > 0)
      {
       info = ereg_replace(string: lines[1], pattern: '^ *"(.*)" *$', replace: "\1");
       if (strlen(info) == 0) info = lines[1];
       security_note(port: port, extra:'\nThe device INFO ID is:\n\n  '+info);
      }
    else
     security_note(port: port);
    register_service(port: port, proto: 'jetdirect');
    set_kb_item(name: 'devices/hp_printer', value: TRUE);
   }
   close(s);
  }
 }
