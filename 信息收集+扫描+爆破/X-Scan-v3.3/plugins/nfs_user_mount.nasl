#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15984);
 script_version ("$Revision: 1.6 $");
 
 script_name(english:"NFS Share User Mountable");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to access the remote NFS shares without having root privileges." );
 script_set_attribute(attribute:"description", value:
"Some of the NFS shares exported by the remote server could be
mounted by the scanning host. An attacker may exploit this problem
to gain read (and possibly write) access to files on remote host.

Note that root privileges were not required to mount the remote shares. That is,
the source port to mount the shares was bigger than 1024." );
 script_set_attribute(attribute:"solution", value:
"Configure NFS on the remote host so that only authorized hosts can mount
the remote shares.

The remote NFS server should prevent mount requests originating from a non-privileged port." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for User Mountable NFS");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Renaud Deraison (modified 2004 Michael Stone)");
 script_family(english:"RPC");
 script_dependencie("rpc_portmap.nasl", "showmount.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("nfs_func.inc");

mountable = NULL;

list = get_kb_list("nfs/exportlist");
if(isnull(list))exit(0);
shares = make_list(list);

port = get_rpc_port(program:100005, protocol:IPPROTO_UDP);
if ( ! port ) exit(0);
soc = open_sock_udp(port);

port2 = get_rpc_port(program:100003, protocol:IPPROTO_UDP);
if ( ! port2 ) exit(0);
soc2 = open_sock_udp(port2);

if(!soc)exit(0);

foreach share (shares)
{
 fid = nfs_mount(soc:soc, share:share);
 if(fid)
 {
  content = nfs_readdir(soc:soc2, fid:fid);
  mountable += '+ ' + share + '\n' ;
  flag = 0;
  foreach c (content)
  {
   if(flag == 0){
   	mountable += ' + Contents of ' + share + ' : \n';
   	flag = 1;
	}
    mountable += ' - ' + c + '\n'; 
  }
  nfs_umount(soc:soc, share:share);
  mountable += '\n\n';
 }
}

close(soc);

if(mountable)
{
 report = 'The following NFS shares could be mounted without root privileges: \n'
  + mountable;
 security_hole(port:2049, proto:"udp", extra:report);
}		 
