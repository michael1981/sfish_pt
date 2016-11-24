#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(25203);
 script_version ("$Revision: 1.8 $");
 
 script_name(english:"Enumerate IPv4 Interfaces via SSH");
             
 script_set_attribute(attribute:"synopsis", value:
"This plugin enumerates IPv4 interfaces on a remote host." );
 script_set_attribute(attribute:"description", value:
"By connecting to the remote host via SSH with the supplied
credentials, this plugin enumerates network interfaces configured with
IPv4 addresses." );
 script_set_attribute(attribute:"solution", value:
"Disable any unused IPv4 interfaces." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();

 
 script_summary(english:"Uses the result of ifconfig -a");

 script_category(ACT_GATHER_INFO);
 script_family(english:"General");
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 script_dependencie("ssh_get_info.nasl");
 script_require_keys("Host/ifconfig");
 exit(0);
}



ifconfig = get_kb_item("Host/ifconfig");
if ( isnull(ifconfig) ) exit(0);
inet = egrep(pattern:"inet[^6]", string:ifconfig);
if ( isnull(inet) ) exit(0);


ifaces = NULL;
dev    = NULL;
lines = split(ifconfig, keep:FALSE);
foreach line ( lines )
{
 if ( line =~ "^([a-z]+[a-z0-9]+(:[0-9]+)?)[: ].*" ) 
        {
         dev = ereg_replace(pattern:"^([a-z]+[a-z0-9]+(:[0-9]+)?)[: ].*", replace:"\1", string:line);
	 if ( dev == line ) dev = NULL;
	}

 if  ( "inet" >< line && "inet6" >!< line )
 {
  addr = ereg_replace(pattern:".*inet( addr:)? ?([0-9.]+).*", string:line, replace:"\2");
  if ( addr != line )
  {
   ifaces += ' - ' + addr;
   if ( !isnull(dev) ) ifaces += ' (on interface ' + dev + ')';
   ifaces += '\n';
  }
 }
}



if ( strlen(ifaces) )
{
 security_note(port:0, extra:'\nThe following IPv4 addresses are set on the remote host :\n\n' + ifaces);
}
