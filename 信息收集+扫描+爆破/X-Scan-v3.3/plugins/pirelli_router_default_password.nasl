#

# Changes by Tenable:
# - Revised plugin title, formatted output (8/20/09)


include("compat.inc");

if(description)
{
   script_id(12641);
   script_version ("$Revision: 1.8 $");
   script_cve_id("CVE-1999-0502");
 
   script_name(english:"Pirelli AGE mB Router Default Password (microbusiness) for 'admin' Account");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host can be accessed by known default credentials." );
 script_set_attribute(attribute:"description", value:
"The remote host is a Pirelli AGE mB (microBusiness) router with its 
default password set (admin/microbusiness).

An attacker could telnet to it and reconfigure it to lock the owner out 
and to prevent him from using his Internet connection, and do bad things." );
 script_set_attribute(attribute:"solution", value:
"Telnet to this router and set a new password immediately." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

   script_summary(english:"Logs into the router Pirelli AGE mB");
   script_category(ACT_GATHER_INFO);
   script_copyright(english:"This script is free");
   script_family(english:"Misc.");
   script_require_ports(23);
 
   exit(0);
}

include("default_account.inc");


port = 23;
if(get_port_state(port))
{
 banner = get_telnet_banner(port:port);
 if ( ! banner || "USER:" >!< banner ) exit(0);

 #First try as Admin
soc = open_sock_tcp(port);
 if(soc)
 {
   r = recv_until(socket:soc, pattern:"(USER:|ogin:)");
   if ( "USER:" >!< r ) exit(0); 
   s = string("admin\r\nmicrobusiness\r\n");
   send(socket:soc, data:s);
   r = recv_until(socket:soc, pattern:"Configuration");
   close(soc);
   if( r && "Configuration" >< r )
   {
     security_hole(port);
     exit(0);
   }
 }
 #Second try as User (reopen soc beacause wrong pass disconnect)
 soc = open_sock_tcp(port);
 if(soc)
 {
   r = recv_until(socket:soc, pattern:"(USER:|ogin:)");
   if ( "USER:" >!< r ) exit(0);
   s = string("user\r\npassword\r\n");
   send(socket:soc, data:s);
   r = recv_until(socket:soc, pattern:"Configuration");
   close(soc);
   if( r && "Configuration" >< r )
   {
     security_hole(port);
   }
 }
}

