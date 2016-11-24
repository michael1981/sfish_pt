#
# (C) Tenable Network Security, Inc.
#

# This is a _very_ old flaw

include( 'compat.inc' );

if(description)
{
  script_id(11353);
  script_version ("$Revision: 1.8 $");
  script_cve_id("CVE-1999-0167");
  script_bugtraq_id(32);
  script_xref(name:"OSVDB", value:"889");

  script_name(english:"NFS Predictable Filehandles Filesystem Access");
  script_summary(english:"Checks for NFS");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to access control breach.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote NFS server might allow an attacker to guess
the NFS filehandles, and therefore allow them to mount
the remote filesystems without the proper authorizations"
  );

  script_set_attribute(
    attribute:'solution',
    value: "Contact your vendor for the appropriate patches."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.cert.org/advisories/CA-1991-21.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"RPC");
 script_dependencie("rpc_portmap.nasl", "os_fingerprint.nasl");
 script_require_keys("rpc/portmap", "Host/OS");
 exit(0);
}




include("misc_func.inc");

os = get_kb_item("Host/OS");
if(!os) exit(0);
if("SunOS 4" >!< os) exit(0);

#----------------------------------------------------------------------------#
#                              Here we go                                    #
#----------------------------------------------------------------------------#

security_problem = 0;
list = "";
number_of_shares = 0;
port = get_rpc_port(program:100005, protocol:IPPROTO_TCP);
soc = 0;
if(!port)
{
 port = get_rpc_port(program:100005, protocol:IPPROTO_UDP);
 if(!port)exit(0);
}

security_warning(port);
