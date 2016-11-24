#TRUSTED 7ac94c39b5fadfa6942dc9d2a9b40e100a17181d7ed5bb19865cae3b3339f516e07dd126ae66df1ba2a16e62156d8c70ae3c97cdaa32becff98c6aebeb5d77eca09578a108c6ab8145da1f51451107973fd839c00692506e583fa2559c9bf42426951f2d83978f0ebe147f65513b68a8f223e3d917ef0b019985e12b3b67b1b4b78547e46747736b5e4f5b921e5df3b27a00171bc2db0a22a7e139af97ebc060e2369e1b04bfeb4b4a08e7eb8bfd65093f69cf45f519890d840b484940e12f44132affe9e69d8ac4e6a4d7c4cb35599d788a55d47cbcb0500332f32df151405d8657cea45e3a6abb9128402c7db8ea6de66a744f565fe9c9585fb26e14c834c3075f2141ba6d50fe6877af66a121b5560ac402e36859bbd677fd35b3ec334d71974f51ce26d36d9714c4400f63997584d1ffa16eca2882bc82063c7c957f0e617e0d3f00225d4506ece191ee3a6bef49a2e1156fafd990581a060a1429c0fa6797f6f39a50725079cb29958aeaf60b281896d5164e9d7e517ae61bb0917dcef9c36b8575dc0040155febb9678b5dbc5e8e7cfd74095306768fee97aa705b40ea8f5b973d7b973e2beb6e5aac5e08fa8d98078d77e71b0a10a106d916ed9119bba61ef47732b1bba8452e652b09bb26fc15d143bd1efbd75aaa9e9970378f0a86cb6e5fa8a806e8a4f97e71da443b9a6996f078fdb1ab20a95309e6f3e8c7413f
#
# (C) Tenable Network Security, Inc.
#
#

include("compat.inc");

if(description)
{
 script_id(25221);
 script_version ("1.5");

 script_name(english: "Remote listeners enumeration");
 
 script_set_attribute(attribute:"synopsis", value:
"Using netstat, it is possible to identify what daemon or service is running 
on each remote port." );
 script_set_attribute(attribute:"description", value:
"By using the Linux-specific 'netstat -anp' command and by logging into the
remote host, it is possible to obtain the names of the processes listening 
on the remote ports." );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"risk_factor", value:
"None" );
 script_end_attributes();
 
 script_summary(english: "Find which process is listening on each port with netstat");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 script_family(english: "Service detection");

 script_dependencies("ssh_settings.nasl", "ssh_get_info.nasl");
 script_require_ports("Services/ssh", 22);
 script_require_keys("Host/uname");
 exit(0);
}


include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

# We may support other protocols here
if ( islocalhost() )
 info_t = INFO_LOCAL;
else
{
 sock_g = ssh_open_connection();
 if (! sock_g) exit(0);
 info_t = INFO_SSH;
}

uname = get_kb_item("Host/uname");
if (! uname) exit(0);

ip = get_host_ip();
buf = "";
found = 0;
ostype = '';

seen = make_list();

if ( 'Linux' >!< uname ) exit(0);
buf = info_send_cmd(cmd: 'LC_ALL=C netstat -anp');
if (strlen(buf) == 0) exit(0);
set_kb_item(name: "Host/netstat_anp", value: buf);

foreach line (split(buf, keep: 0))
  {
    v = eregmatch(string: line, pattern: '^(tcp|udp)[ \t]+[0-9]+[ \t]+[0-9]+[ \t]+([0-9]+\\.[0-9.]+):([0-9]+)[ \t]+([0-9]+\\.[0-9.]+):[0-9*]+[ \t]+(LISTEN[ \t]+)?([0-9]+)/([^ \t].*)?[ \t]*$');
    if (isnull(v))	# Try IPv6 *even* if the target is IPv4
     v = eregmatch(string: line, pattern: '^(tcp|udp)6?[ \t]+[0-9]+[ \t]+[0-9]+[ \t]+([0-9a-f:]+):([0-9]+)[ \t]+([0-9a-f:]+):[0-9*]+[ \t]+(LISTEN[ \t]+)?([0-9]+)/([^ \t].*)?[ \t]*$');
   if (isnull(v)) continue;

   p = int(v[3]); 
   if ( p < 0 || p > 65535 ) continue;
   proto = tolower(v[1]); 
   if ( proto != "tcp" && proto != "udp" ) continue;
   pid = int(v[6]);
   if (pid > 0)
    {
      exe = info_send_cmd(cmd: 'readlink \'/proc/'+pid+'/exe\' 2>/dev/null');
      exe = chomp(exe);
    }
    else
      exe = '';
   if (strlen(exe) == 0)  exe = chomp(v[7]);
   if (strlen(exe) == 0) continue;

   k = strcat(proto, '/', p);
   if (seen[k]) continue;
   seen[k] = exe;

   set_kb_item(name: 'Host/Daemons/'+v[2]+'/'+proto+'/'+p, value: exe);

   if ( TARGET_IS_IPV6 && (v[2] == "::" || v[2] == ip) ||
       !TARGET_IS_IPV6 && (v[2] == '0.0.0.0' || v[2] == ip || v[2] == "::") )
   {
     set_kb_item(name: 'Host/Listeners/'+proto+'/'+p, value: exe);
     found ++;
     security_note(port: p, proto: proto, data:
'The Linux process \''+exe+ '\' is listening on this port');
   }
 }
 if ( found ) set_kb_item(name:"Host/Listeners/Check", value:"netstat -anp");
